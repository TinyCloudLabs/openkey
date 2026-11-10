import { afterAll, beforeAll, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import type { Server } from 'bun';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { decodeJwt, SignJWT } from 'jose';
import type * as DatabaseModule from '@openkey/db';
import type * as AuthModule from '../apps/api/src/auth';

// TC-1231 (plan TC-1188 §4 "Deletion", "Notifications", continuation revoke and
// R9): real API, real migrations, stubbed Apple token/revoke/JWKS endpoints.
const backend = process.env.TC1231_APPLE_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');
const SERVICES_ID = 'so.openkey.test';
const APP_ID = 'so.openkey.test.app';
const TEAM_ID = 'TC1231TEAM';
const KID = 'tc1231-key';
const API = 'https://api.openkey.test';
const ORIGIN = 'https://openkey.test';
const CALLBACK = `${ORIGIN}/auth/social/callback`;

if (!backend) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  for (const engine of ['pglite', 'postgres', 'disabled']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(`TC-1231 Apple revocation, deletion and lock (${engine})`, async () => {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: {
          ...process.env,
          TC1231_APPLE_TEST_CHILD: engine,
          NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: API,
          BETTER_AUTH_SECRET: 'tc1231-isolated-regression-secret-not-for-production',
          WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: ORIGIN, CORS_ORIGIN: ORIGIN,
          ADMIN_API_KEY: 'tc1231-admin-key', RESEND_API_KEY: 'tc1231-resend-stub',
          GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
          APPLE_SIGN_IN_ENABLED: engine === 'disabled' ? 'false' : 'true',
          APPLE_NATIVE_SIGN_IN_ENABLED: 'false',
          APPLE_CLIENT_ID: SERVICES_ID, APPLE_TEAM_ID: TEAM_ID,
          APPLE_KEY_ID: KID, APPLE_PRIVATE_KEY: pem,
          APPLE_WEBHOOK_AUDIENCE: APP_ID,
        },
        stdout: 'pipe', stderr: 'pipe',
      });
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
      ]);
      expect(exitCode, stdout + stderr).toBe(0);
    }, 300_000);
  }
} else {
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc1231-'));
  const databaseName = `tc1231_${randomUUID().replaceAll('-', '')}`;
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const { privateKey: forgedKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };
  const originalFetch = globalThis.fetch;
  let httpServer: Server<undefined>;
  let admin: Client | undefined;
  let prisma: DatabaseModule.PrismaClient;
  let auth: typeof AuthModule.auth;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  const profiles = new Map<string, { claims: Record<string, unknown>; refreshToken: string }>();
  const revoked: Array<{ token: string; clientId: string }> = [];
  let failRevocation = false;
  const mail: Array<{ to: string; subject: string; html: string }> = [];
  const nativeCeiling = { version: 1, appId: 'xyz.tinycloud.tinychat', tinycloudHost: 'https://tee.node.tinycloud.xyz',
    kv: { paths: ['xyz.tinycloud.tinychat/threads/'], actions: ['get', 'put', 'list'] }, sql: null,
    maxDelegationTtlSeconds: 3600, grantLifetimeSeconds: 30 * 86400 };

  function cookies(response: Response): string {
    return response.headers.getSetCookie().map((cookie) => cookie.split(';')[0]).join('; ');
  }
  function combineCookies(...parts: string[]): string {
    return parts.filter(Boolean).join('; ');
  }
  function call(path: string, init: RequestInit = {}) {
    return originalFetch(`http://127.0.0.1:${httpServer.port}${path}`, { ...init, redirect: 'manual' });
  }
  function post(path: string, body: unknown, cookie = '', headers: Record<string, string> = {}) {
    return call(path, {
      method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json', cookie, ...headers },
      body: JSON.stringify(body),
    });
  }
  function get(path: string, cookie = '', headers: Record<string, string> = {}) {
    return call(path, { headers: { origin: ORIGIN, cookie, ...headers } });
  }
  function form(path: string, body: URLSearchParams, cookie = '') {
    return call(path, {
      method: 'POST', headers: { origin: 'https://appleid.apple.com', 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: body.toString(),
    });
  }
  function location(response: Response): URL {
    const target = response.headers.get('location');
    expect(target).toBeTruthy();
    return new URL(target!);
  }
  async function sign(claims: Record<string, unknown>, key = privateKey): Promise<string> {
    return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: KID }).sign(key);
  }
  function profile(sub: string, email?: string, overrides: Record<string, unknown> = {}) {
    const now = Math.floor(Date.now() / 1000);
    return {
      iss: 'https://appleid.apple.com', aud: SERVICES_ID, sub, iat: now, exp: now + 3600,
      ...(email ? { email, email_verified: true } : {}), ...overrides,
    };
  }
  async function startApple(cookie = '', link = false) {
    const start = await post(link ? '/api/auth/link-social' : '/api/auth/sign-in/social', {
      provider: 'apple', callbackURL: CALLBACK, errorCallbackURL: CALLBACK, disableRedirect: true,
    }, cookie);
    expect(start.status, await start.clone().text()).toBe(200);
    const state = new URL((await start.json() as { url: string }).url).searchParams.get('state');
    expect(state).toBeTruthy();
    return { start, state: state! };
  }
  async function appleCallback(claims: Record<string, unknown>, cookie = '', link = false) {
    const { start, state } = await startApple(cookie, link);
    const code = randomUUID();
    profiles.set(code, { claims, refreshToken: `refresh-${randomUUID()}` });
    const posted = await form('/api/auth/callback/apple', new URLSearchParams({ state, code }), combineCookies(cookie, cookies(start)));
    const redirected = location(posted);
    return call(`${redirected.pathname}${redirected.search}`, {
      headers: { cookie: combineCookies(cookie, cookies(start), cookies(posted)) },
    });
  }
  async function signedInCookie(email: string): Promise<string> {
    const otp = await auth.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
    const response = await post('/api/auth/sign-in/email-otp', { email, otp });
    expect(response.status, await response.clone().text()).toBe(200);
    return cookies(response);
  }
  async function latestSession(userId: string) {
    return prisma.session.findFirstOrThrow({ where: { userId }, orderBy: { createdAt: 'desc' } });
  }
  async function stepUp(cookie: string, userId: string, purpose?: 'delete_account') {
    const send = await post('/api/account/step-up/email-otp/send', purpose ? { purpose } : {}, cookie);
    expect(send.status, await send.clone().text()).toBe(200);
    const session = await latestSession(userId);
    const prefix = purpose ? 'openkey-account-delete-otp' : 'openkey-account-step-up-otp';
    const verification = await prisma.verification.findFirstOrThrow({ where: { identifier: { startsWith: `${prefix}:${session.id}:` } } });
    const verified = await post('/api/account/step-up/email-otp/verify', {
      code: verification.value.split(':')[0], ...(purpose ? { purpose } : {}),
    }, cookie);
    expect(verified.status, await verified.clone().text()).toBe(200);
  }
  /** A user created through the Apple continuation, signed in, with its stored Apple refresh token. */
  async function appleUser(sub: string, email: string) {
    const response = await appleCallback(profile(sub, email));
    expect(location(response).searchParams.get('error')).toBe('new_account');
    const continuation = location(response).searchParams.get('continuation')!;
    const created = await post('/api/auth/social/confirm', { continuation }, cookies(response));
    expect(created.status, await created.clone().text()).toBe(200);
    const user = await prisma.user.findUniqueOrThrow({ where: { email } });
    const account = await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple', accountId: sub } });
    return { user, account, cookie: cookies(created) };
  }
  async function sessionUser(cookie: string, headers: Record<string, string> = {}): Promise<string | null> {
    const response = await get('/api/auth/get-session', cookie, headers);
    const body = await response.json() as { user?: { id: string } } | null;
    return body?.user?.id ?? null;
  }
  async function notify(
    type: string,
    sub: string,
    options: { eventTime?: number; jti?: string; key?: typeof privateKey; aud?: string; eventsAsString?: boolean } = {},
  ) {
    const events = { type, sub, event_time: options.eventTime ?? Math.floor(Date.now() / 1000) };
    const payload = await sign({
      iss: 'https://appleid.apple.com', aud: options.aud ?? APP_ID, iat: Math.floor(Date.now() / 1000),
      jti: options.jti ?? randomUUID(), events: options.eventsAsString === false ? events : JSON.stringify(events),
    }, options.key);
    return call('/api/webhooks/apple', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ payload }),
    });
  }
  async function nativeClient(): Promise<string> {
    const response = await call('/api/admin/oauth/clients', { method: 'POST',
      headers: { Authorization: 'Bearer tc1231-admin-key', 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: `TC-1231 ${randomUUID()}`, type: 'native', redirectUris: ['xyz.tinycloud.exo://openkey/callback'], tinycloudNativeDelegation: nativeCeiling }) });
    expect(response.status, await response.clone().text()).toBe(201);
    return (await response.json() as { client: { clientId: string } }).client.clientId;
  }
  /** A live native grant with its refresh and access tokens, plus an unrelated OAuth token pair. */
  async function seedAppAccess(userId: string) {
    const clientId = await nativeClient();
    const key = await prisma.ethereumKey.findFirstOrThrow({ where: { userId } });
    const refreshHash = `hash-${randomUUID()}`;
    await prisma.tinyCloudNativeGrant.create({ data: { id: `grant-${randomUUID()}`, userId, clientId, consentId: 'consent',
      consentGeneration: 0n, keyId: key.id, address: key.address, sessionDid: 'did:key:z#z', sessionJwk: { kty: 'OKP' },
      sessionJkt: 'jkt', spaceId: 'space', approvedPermissions: [], ttlSeconds: 3600, tinycloudHost: nativeCeiling.tinycloudHost,
      refreshTokenHash: refreshHash, absoluteExpiresAt: new Date(Date.now() + 86_400_000) } });
    const refresh = await prisma.oauthRefreshToken.create({ data: { id: randomUUID(), token: refreshHash, clientId, userId,
      scopes: ['openid', 'offline_access', 'tinycloud:delegation'], expiresAt: new Date(Date.now() + 86_400_000) } });
    await prisma.oauthAccessToken.create({ data: { id: randomUUID(), token: `access-${randomUUID()}`, clientId, userId,
      refreshId: refresh.id, scopes: ['openid'], expiresAt: new Date(Date.now() + 300_000) } });
    await prisma.oauthRefreshToken.create({ data: { id: randomUUID(), token: `other-${randomUUID()}`, clientId, userId,
      scopes: ['openid', 'offline_access'], expiresAt: new Date(Date.now() + 86_400_000) } });
    return clientId;
  }
  async function outcome(jti: string) {
    return (await prisma.appleNotification.findUniqueOrThrow({ where: { jti } })).outcome;
  }

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    let connectionString: string;
    if (backend === 'postgres') {
      if (!postgresUrl) throw new Error('OPENKEY_TEST_POSTGRES_URL is required');
      admin = new Client({ connectionString: postgresUrl });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${databaseName}"`);
      const target = new URL(postgresUrl);
      target.pathname = `/${databaseName}`;
      connectionString = target.toString();
      const migrationConnection = new Client({ connectionString });
      await migrationConnection.connect();
      try {
        for (const migration of migrations) {
          await migrationConnection.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
        }
      } finally { await migrationConnection.end(); }
    } else {
      const database = new PGlite(directory);
      try {
        for (const migration of migrations) {
          await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
        }
      } finally { await database.close(); }
      connectionString = `pglite:${directory}`;
    }
    process.env.DATABASE_URL = connectionString;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === 'https://appleid.apple.com/auth/token') {
        const body = new URLSearchParams(String(init?.body));
        const code = body.get('code');
        const supplied = profiles.get(code ?? '');
        if (!supplied || body.get('client_id') !== SERVICES_ID) return Response.json({ error: 'invalid_grant' }, { status: 400 });
        const secret = body.get('client_secret');
        if (!secret || decodeJwt(secret).sub !== SERVICES_ID || decodeJwt(secret).iss !== TEAM_ID) {
          return Response.json({ error: 'invalid_client' }, { status: 401 });
        }
        profiles.delete(code!);
        return Response.json({ access_token: `access-${code}`, refresh_token: supplied.refreshToken,
          token_type: 'Bearer', expires_in: 3600, id_token: await sign(supplied.claims) });
      }
      if (url === 'https://appleid.apple.com/auth/keys') return Response.json({ keys: [jwk] });
      if (url === 'https://appleid.apple.com/auth/revoke') {
        const body = new URLSearchParams(String(init?.body));
        revoked.push({ token: body.get('token') ?? '', clientId: body.get('client_id') ?? '' });
        return new Response('', { status: failRevocation ? 503 : 200 });
      }
      if (url.startsWith('https://appleid.apple.com/')) throw new Error(`Unexpected Apple network request: ${url}`);
      if (url.startsWith('https://api.resend.com/')) {
        const body = JSON.parse(String(init?.body ?? '{}')) as { to?: string | string[]; subject?: string; html?: string };
        mail.push({ to: Array.isArray(body.to) ? body.to[0]! : body.to ?? '', subject: body.subject ?? '', html: body.html ?? '' });
        return Response.json({ id: randomUUID() });
      }
      return originalFetch(input, init);
    }) as typeof fetch;
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    ({ auth } = await import('../apps/api/src/auth'));
    app = (await import('../apps/api/src/index')).default;
    httpServer = Bun.serve({
      hostname: '127.0.0.1', port: 0,
      fetch: (request) => {
        const url = new URL(request.url);
        return app.fetch(new Request(API + url.pathname + url.search, request));
      },
    });
  }, 120_000);

  afterAll(async () => {
    globalThis.fetch = originalFetch;
    httpServer?.stop(true);
    await prisma?.$disconnect();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await admin.end();
    }
    await rm(directory, { recursive: true, force: true });
  });
  beforeEach(async () => {
    profiles.clear(); revoked.length = 0; mail.length = 0; failRevocation = false;
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "user", "verification", "apple_social_continuation", "apple_notification", "oauth_client" CASCADE');
  });

  if (backend === 'disabled') {
    test('the Apple webhook is not found while Apple sign-in is disabled', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'off@openkey.test', emailVerified: true } });
      await prisma.account.create({ data: { id: randomUUID(), userId: user.id, providerId: 'apple', accountId: 'off-sub' } });
      await prisma.session.create({ data: { id: randomUUID(), userId: user.id, token: randomUUID(), expiresAt: new Date(Date.now() + 3_600_000) } });
      const response = await notify('consent-revoked', 'off-sub');
      expect(response.status).toBe(404);
      expect(await prisma.appleNotification.count()).toBe(0);
      expect(await prisma.session.count({ where: { userId: user.id } })).toBe(1);
    });
  } else {

  describe('account deletion (D6)', () => {
    test('a passkey-less user deletes with a fresh deletion code; continuation tokens are revoked with their client', async () => {
      const { user, cookie } = await appleUser('delete-sub', 'delete@openkey.test');
      expect(await prisma.ethereumKey.count({ where: { userId: user.id } })).toBe(1);
      const body = { confirmation: 'DELETE MY ACCOUNT' };
      const unverified = await post('/api/account/delete', body, cookie);
      expect(unverified.status).toBe(403);
      expect((await unverified.json() as { code: string }).code).toBe('email_step_up_required');
      // A linking code is a different purpose and never authorizes deletion.
      await stepUp(cookie, user.id);
      expect((await post('/api/account/delete', body, cookie)).status).toBe(403);
      await stepUp(cookie, user.id, 'delete_account');
      expect(mail.some((message) => message.to === user.email && /delete your OpenKey account/i.test(message.subject))).toBe(true);
      const deleted = await post('/api/account/delete', body, cookie);
      expect(deleted.status, await deleted.clone().text()).toBe(200);
      expect(await prisma.user.count({ where: { id: user.id } })).toBe(0);
      expect(await prisma.ethereumKey.count({ where: { userId: user.id } })).toBe(0);
      expect(await prisma.account.count({ where: { userId: user.id } })).toBe(0);
      expect(revoked).toEqual([{ token: expect.stringMatching(/^refresh-/), clientId: SERVICES_ID }]);
    });

    test('a deletion code older than five minutes is refused, and is single use', async () => {
      const { user, cookie } = await appleUser('stale-delete-sub', 'stale-delete@openkey.test');
      await stepUp(cookie, user.id, 'delete_account');
      await prisma.verification.updateMany({
        where: { identifier: { startsWith: 'openkey-account-delete-step-up:' } },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      const stale = await post('/api/account/delete', { confirmation: 'DELETE MY ACCOUNT' }, cookie);
      expect(stale.status).toBe(403);
      expect(await prisma.user.count({ where: { id: user.id } })).toBe(1);
      expect(revoked).toHaveLength(0);
    });

    test('a user with a passkey still needs a fresh passkey; a mailbox code cannot delete', async () => {
      const { user, cookie } = await appleUser('passkey-delete-sub', 'passkey-delete@openkey.test');
      await prisma.passkey.create({ data: {
        id: randomUUID(), userId: user.id, publicKey: 'pk', credentialID: randomUUID(), deviceType: 'singleDevice', backedUp: false,
      } });
      const send = await post('/api/account/step-up/email-otp/send', { purpose: 'delete_account' }, cookie);
      expect(send.status).toBe(403);
      expect((await send.json() as { code: string }).code).toBe('passkey_step_up_required');
      const session = await latestSession(user.id);
      // Even a deletion marker on the session does not stand in for the passkey.
      await prisma.verification.create({ data: {
        id: randomUUID(), identifier: `openkey-account-delete-step-up:${session.id}`, value: 'forged',
        expiresAt: new Date(Date.now() + 300_000),
      } });
      const refused = await post('/api/account/delete', { confirmation: 'DELETE MY ACCOUNT' }, cookie);
      expect(refused.status).toBe(403);
      expect((await refused.json() as { code: string }).code).toBe('passkey_step_up_required');
      expect(await prisma.user.count({ where: { id: user.id } })).toBe(1);
      await prisma.session.update({ where: { id: session.id }, data: { lastPasskeyAt: new Date() } });
      expect((await post('/api/account/delete', { confirmation: 'DELETE MY ACCOUNT' }, cookie)).status).toBe(200);
      expect(await prisma.user.count({ where: { id: user.id } })).toBe(0);
    });

    test('a failing Apple revoke is retried three times, logged without the token, and never restores the account', async () => {
      const { user, cookie } = await appleUser('revoke-fail-sub', 'revoke-fail@openkey.test');
      await prisma.account.updateMany({ where: { userId: user.id, providerId: 'apple' }, data: { appleClientId: 'xyz.tinycloud.home' } });
      await stepUp(cookie, user.id, 'delete_account');
      failRevocation = true;
      const lines: string[] = [];
      const write = process.stdout.write.bind(process.stdout);
      const spy = spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array, ...rest: unknown[]) => {
        lines.push(String(chunk));
        return write(chunk, ...(rest as []));
      }) as never);
      let response: Response;
      try {
        response = await post('/api/account/delete', { confirmation: 'DELETE MY ACCOUNT' }, cookie);
      } finally {
        spy.mockRestore();
      }
      expect(response.status).toBe(200);
      expect(await prisma.user.count({ where: { id: user.id } })).toBe(0);
      expect(revoked).toHaveLength(4);
      expect(new Set(revoked.map(({ clientId }) => clientId))).toEqual(new Set(['xyz.tinycloud.home']));
      const failures = lines.filter((line) => line.includes('auth_apple_revoke_failed'));
      expect(failures).toHaveLength(1);
      expect(failures[0]).not.toContain(revoked[0]!.token);
      expect(lines.join('')).not.toContain(revoked[0]!.token);
    });
  });

  describe('Apple server-to-server notifications', () => {
    test('a stub-signed consent-revoked ends sessions, native grants and OAuth tokens but keeps the user, keys and link', async () => {
      const { user, cookie } = await appleUser('revoke-sub', 'revoke@openkey.test');
      await seedAppAccess(user.id);
      expect(await sessionUser(cookie)).toBe(user.id);
      const jti = randomUUID();
      const response = await notify('consent-revoked', 'revoke-sub', { jti });
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await outcome(jti)).toBe('revoked');
      expect(await sessionUser(cookie)).toBeNull();
      expect(await prisma.session.count({ where: { userId: user.id } })).toBe(0);
      const grants = await prisma.tinyCloudNativeGrant.findMany({ where: { userId: user.id } });
      expect(grants.map(({ status, revokedReason }) => [status, revokedReason])).toEqual([['REVOKED', 'apple_consent_revoked']]);
      expect(await prisma.oauthRefreshToken.count({ where: { userId: user.id } })).toBe(0);
      expect(await prisma.oauthAccessToken.count({ where: { userId: user.id } })).toBe(0);
      const account = await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple' } });
      expect(account.accountId).toBe('revoke-sub');
      expect(account.refreshToken).toBeNull();
      expect(account.accessToken).toBeNull();
      expect(account.revokedAt).not.toBeNull();
      expect(await prisma.user.count({ where: { id: user.id } })).toBe(1);
      expect(await prisma.ethereumKey.count({ where: { userId: user.id } })).toBe(1);
    });

    test('events sent as an object are processed too', async () => {
      const { user, cookie } = await appleUser('object-sub', 'object@openkey.test');
      expect((await notify('consent-revoked', 'object-sub', { eventsAsString: false })).status).toBe(200);
      expect(await sessionUser(cookie)).toBeNull();
      expect(await prisma.user.count({ where: { id: user.id } })).toBe(1);
    });

    test('a bad signature or audience is refused with 400 and changes nothing', async () => {
      const { user, cookie } = await appleUser('forged-sub', 'forged@openkey.test');
      expect((await notify('consent-revoked', 'forged-sub', { key: forgedKey })).status).toBe(400);
      expect((await notify('consent-revoked', 'forged-sub', { aud: SERVICES_ID })).status).toBe(400);
      expect(await sessionUser(cookie)).toBe(user.id);
      expect(await prisma.appleNotification.count()).toBe(0);
      expect((await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple' } })).refreshToken).not.toBeNull();
    });

    test('a replayed jti is not applied again', async () => {
      const { user } = await appleUser('replay-sub', 'replay@openkey.test');
      const jti = randomUUID();
      const eventTime = Math.floor(Date.now() / 1000);
      expect((await notify('consent-revoked', 'replay-sub', { jti, eventTime })).status).toBe(200);
      // The user signs in again with Apple after the revocation.
      const signedIn = await appleCallback(profile('replay-sub', 'replay@openkey.test'));
      expect(location(signedIn).searchParams.has('error')).toBe(false);
      const restored = cookies(signedIn);
      expect(await sessionUser(restored)).toBe(user.id);
      const replay = await notify('consent-revoked', 'replay-sub', { jti, eventTime: eventTime + 5 });
      expect(replay.status).toBe(200);
      expect(await sessionUser(restored)).toBe(user.id);
      expect(await prisma.appleNotification.count()).toBe(1);
    });

    test.each(['account-deleted', 'account-delete'])('%s revokes access and marks the relay email undeliverable', async (type) => {
      const email = `${type}@privaterelay.appleid.com`;
      const { user, cookie } = await appleUser(`${type}-sub`, email);
      const jti = randomUUID();
      expect((await notify(type, `${type}-sub`, { jti })).status).toBe(200);
      expect(await outcome(jti)).toBe('revoked');
      expect(await sessionUser(cookie)).toBeNull();
      expect(await prisma.user.count({ where: { id: user.id } })).toBe(1);
      expect(await prisma.ethereumKey.count({ where: { userId: user.id } })).toBe(1);
      const account = await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple' } });
      expect(account.appleEmailUndeliverable).toBe(true);
      const fresh = await appleCallback(profile(`${type}-sub`, email));
      const info = await get('/api/account', cookies(fresh));
      expect((await info.json() as { user: { emailUndeliverable: boolean } }).user.emailUndeliverable).toBe(true);
    });

    test.each([
      ['seconds', (ms: number) => Math.floor(ms / 1000)],
      ['milliseconds', (ms: number) => ms],
    ])('a revocation (%s) from before the latest link is ignored: account_exists → step-up → link → late consent-revoked', async (_unit, encode) => {
      const email = 'late-revoke@openkey.test';
      const user = await prisma.user.create({ data: { id: randomUUID(), email, emailVerified: true } });
      const exists = await appleCallback(profile('late-sub', email));
      expect(location(exists).searchParams.get('error')).toBe('account_exists');
      const cookie = await signedInCookie(email);
      await stepUp(cookie, user.id);
      const linked = await appleCallback(profile('late-sub', email), cookie, true);
      expect(location(linked).searchParams.has('error')).toBe(false);
      const account = await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple', accountId: 'late-sub' } });
      expect(account.appleRestoredAt).not.toBeNull();
      const jti = randomUUID();
      const response = await notify('consent-revoked', 'late-sub', { jti, eventTime: encode(account.appleRestoredAt!.getTime() - 60_000) });
      expect(response.status).toBe(200);
      expect(await outcome(jti)).toBe('stale_revocation');
      expect(await sessionUser(cookie)).toBe(user.id);
      const after = await prisma.account.findUniqueOrThrow({ where: { id: account.id } });
      expect(after.refreshToken).toBe(account.refreshToken);
      expect(after.revokedAt).toBeNull();
      // A revocation at or after the link applies.
      const current = randomUUID();
      expect((await notify('consent-revoked', 'late-sub', { jti: current, eventTime: encode(Date.now() + 1000) })).status).toBe(200);
      expect(await outcome(current)).toBe('revoked');
      expect(await sessionUser(cookie)).toBeNull();
    });

    test('a new Apple sign-in by sub restores a revoked link, clears revokedAt and outranks older revocations', async () => {
      const { user } = await appleUser('restore-sub', 'restore@openkey.test');
      const revokedAt = Date.now();
      expect((await notify('consent-revoked', 'restore-sub', { eventTime: Math.floor(revokedAt / 1000) })).status).toBe(200);
      expect((await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple' } })).revokedAt).not.toBeNull();
      const signedIn = await appleCallback(profile('restore-sub', 'restore@openkey.test'));
      expect(location(signedIn).searchParams.has('error')).toBe(false);
      const account = await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple' } });
      expect(account.revokedAt).toBeNull();
      expect(account.refreshToken).not.toBeNull();
      expect(account.appleRestoredAt!.getTime()).toBeGreaterThanOrEqual(Math.floor(revokedAt / 1000) * 1000);
      const late = randomUUID();
      expect((await notify('consent-revoked', 'restore-sub', { jti: late, eventTime: Math.floor(account.appleRestoredAt!.getTime() / 1000) - 30 })).status).toBe(200);
      expect(await outcome(late)).toBe('stale_revocation');
      expect(await sessionUser(cookies(signedIn))).toBe(user.id);
    });

    test('distinct events sharing one event_time are all applied', async () => {
      const { user, cookie } = await appleUser('same-time-sub', 'same-time@privaterelay.appleid.com');
      const eventTime = Math.floor(Date.now() / 1000) + 1;
      const email = randomUUID();
      const revoke = randomUUID();
      expect((await notify('email-disabled', 'same-time-sub', { jti: email, eventTime })).status).toBe(200);
      expect((await notify('consent-revoked', 'same-time-sub', { jti: revoke, eventTime })).status).toBe(200);
      expect(await outcome(email)).toBe('email_updated');
      expect(await outcome(revoke)).toBe('revoked');
      const account = await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple' } });
      expect(account.appleEmailUndeliverable).toBe(true);
      expect(account.revokedAt).not.toBeNull();
      expect(await sessionUser(cookie)).toBeNull();
    });

    test.each([
      ['disabled then enabled', ['email-disabled', 'email-enabled']],
      ['enabled then disabled', ['email-enabled', 'email-disabled']],
    ])('at an equal event_time email-disabled wins (%s); a later email-enabled clears it', async (_order, types) => {
      const { user, cookie } = await appleUser('email-order-sub', 'email-order@privaterelay.appleid.com');
      const eventTime = Math.floor(Date.now() / 1000);
      for (const type of types) expect((await notify(type, 'email-order-sub', { eventTime })).status).toBe(200);
      const flagged = await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple' } });
      expect(flagged.appleEmailUndeliverable).toBe(true);
      expect(flagged.appleEmailEventAt?.getTime()).toBe(eventTime * 1000);
      // Email events never touch sessions, tokens or the user's email.
      expect(await sessionUser(cookie)).toBe(user.id);
      expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).email).toBe(user.email);
      expect((await get('/api/account', cookie).then((r) => r.json()) as { user: { emailUndeliverable: boolean } }).user.emailUndeliverable).toBe(true);
      expect((await notify('email-enabled', 'email-order-sub', { eventTime: eventTime - 10 })).status).toBe(200);
      expect((await prisma.account.findUniqueOrThrow({ where: { id: flagged.id } })).appleEmailUndeliverable).toBe(true);
      expect((await notify('email-enabled', 'email-order-sub', { eventTime: eventTime + 10 })).status).toBe(200);
      expect((await prisma.account.findUniqueOrThrow({ where: { id: flagged.id } })).appleEmailUndeliverable).toBe(false);
    });

    test('an unknown sub records the jti and changes nothing else', async () => {
      const { user, cookie } = await appleUser('known-sub', 'known@openkey.test');
      const jti = randomUUID();
      expect((await notify('consent-revoked', 'never-linked-sub', { jti })).status).toBe(200);
      expect(await outcome(jti)).toBe('unknown_subject');
      expect(await sessionUser(cookie)).toBe(user.id);
    });

    test('event_time more than a day from iat is refused', async () => {
      await appleUser('window-sub', 'window@openkey.test');
      const response = await notify('consent-revoked', 'window-sub', { eventTime: Math.floor(Date.now() / 1000) - 2 * 86_400 });
      expect(response.status).toBe(400);
      expect(await prisma.appleNotification.count()).toBe(0);
    });
  });

  describe('locked accounts (R9)', () => {
    test('a locked user\'s live cookie and bearer sessions are refused by session lookup and the signing routes', async () => {
      const { user, cookie } = await appleUser('locked-sub', 'locked@openkey.test');
      const key = await prisma.ethereumKey.findFirstOrThrow({ where: { userId: user.id } });
      const token = (await latestSession(user.id)).token;
      const bearer = { authorization: `Bearer ${token}` };
      expect(await sessionUser('', bearer)).toBe(user.id);
      expect((await post(`/api/keys/${key.id}/sign`, { message: 'before lock' }, cookie)).status).toBe(200);
      expect((await post(`/api/keys/${key.id}/sign`, { message: 'before lock' }, '', bearer)).status).toBe(200);
      const nostr = (headers: Record<string, string>, cookieHeader = '') => post('/api/keys/nostr/key_missing/sign-event', {
        clientOrigin: 'https://client.example', event: {},
      }, cookieHeader, headers);
      expect((await nostr({}, cookie)).status).not.toBe(401);
      expect((await post('/api/delegate/sign', {}, cookie)).status).not.toBe(401);

      await prisma.user.update({ where: { id: user.id }, data: { lockedAt: new Date() } });
      expect(await prisma.session.count({ where: { userId: user.id } })).toBe(1);
      expect(await sessionUser(cookie)).toBeNull();
      expect(await sessionUser('', bearer)).toBeNull();
      expect((await post(`/api/keys/${key.id}/sign`, { message: 'after lock' }, cookie)).status).toBe(401);
      expect((await post(`/api/keys/${key.id}/sign`, { message: 'after lock' }, '', bearer)).status).toBe(401);
      expect((await nostr({}, cookie)).status).toBe(401);
      expect((await nostr(bearer)).status).toBe(401);
      expect((await post('/api/delegate/sign', {}, cookie)).status).toBe(401);
      expect((await get('/api/account', cookie)).status).toBe(401);
      expect(await prisma.ethereumKey.count({ where: { userId: user.id } })).toBe(1);
    });
  });
  }
}
