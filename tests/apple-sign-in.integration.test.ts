import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import type { Server } from 'bun';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { symmetricDecrypt, symmetricEncrypt } from 'better-auth/crypto';
import { decodeJwt, SignJWT } from 'jose';
import { recoverMessageAddress } from 'viem';
import type * as DatabaseModule from '@openkey/db';
import type * as AuthModule from '../apps/api/src/auth';

// Run against the real API and migrations, isolated from tests that mock auth or DB modules.
const backend = process.env.TC1230_APPLE_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');
const SERVICES_ID = 'so.openkey.test';
const TEAM_ID = 'TC1230TEAM';
const KID = 'tc1230-key';
const API = 'https://api.openkey.test';
const ORIGIN = 'https://openkey.test';
const CALLBACK = `${ORIGIN}/auth/social/callback`;

if (!backend) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  for (const engine of ['pglite', 'postgres', 'disabled']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(`TC-1230 Apple sign-in (${engine})`, async () => {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: {
          ...process.env,
          TC1230_APPLE_TEST_CHILD: engine,
          NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: API,
          BETTER_AUTH_SECRET: 'tc1230-isolated-regression-secret-not-for-production',
          WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: ORIGIN, CORS_ORIGIN: ORIGIN,
          ADMIN_API_KEY: 'tc1230-admin-key', RESEND_API_KEY: 'tc1230-resend-stub',
          GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
          APPLE_SIGN_IN_ENABLED: engine === 'disabled' ? 'false' : 'true',
          APPLE_NATIVE_SIGN_IN_ENABLED: 'false',
          APPLE_CLIENT_ID: SERVICES_ID, APPLE_TEAM_ID: TEAM_ID,
          APPLE_KEY_ID: KID, APPLE_PRIVATE_KEY: pem,
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
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc1230-'));
  const databaseName = `tc1230_${randomUUID().replaceAll('-', '')}`;
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };
  const originalFetch = globalThis.fetch;
  let httpServer: Server<undefined>;
  const originalSetInterval = globalThis.setInterval;
  let sweep: (() => Promise<void>) | undefined;
  let admin: Client | undefined;
  let prisma: DatabaseModule.PrismaClient;
  let auth: typeof AuthModule.auth;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  const profiles = new Map<string, { claims: Record<string, unknown>; refreshToken: string }>();
  const revoked: Array<{ token: string; clientId: string }> = [];
  let failRevocation = false;
  const mail: Array<{ to: string; subject: string; html: string }> = [];

  function cookies(response: Response): string {
    return response.headers.getSetCookie().map((cookie) => cookie.split(';')[0]).join('; ');
  }
  function combineCookies(...parts: string[]): string {
    return parts.filter(Boolean).join('; ');
  }
  function call(path: string, init: RequestInit = {}) {
    return originalFetch(`http://127.0.0.1:${httpServer.port}${path}`, { ...init, redirect: 'manual' });
  }
  function post(path: string, body: unknown, cookie = '') {
    return call(path, {
      method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json', cookie },
      body: JSON.stringify(body),
    });
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
  function sessionCookie(response: Response): boolean {
    return cookies(response).includes('session_token=');
  }
  async function sign(claims: Record<string, unknown>): Promise<string> {
    return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: KID }).sign(privateKey);
  }
  function profile(sub: string, email?: string, overrides: Record<string, unknown> = {}) {
    const now = Math.floor(Date.now() / 1000);
    return {
      iss: 'https://appleid.apple.com', aud: SERVICES_ID, sub, iat: now, exp: now + 3600,
      ...(email ? { email, email_verified: true } : {}), ...overrides,
    };
  }
  async function startApple(cookie = '', link = false, callbackURL = CALLBACK) {
    const start = await post(link ? '/api/auth/link-social' : '/api/auth/sign-in/social', {
      provider: 'apple', callbackURL, errorCallbackURL: callbackURL, disableRedirect: true,
    }, cookie);
    expect(start.status, await start.clone().text()).toBe(200);
    const url = new URL((await start.json() as { url: string }).url);
    expect(url.origin).toBe('https://appleid.apple.com');
    expect(url.searchParams.get('response_mode')).toBe('form_post');
    const state = url.searchParams.get('state');
    expect(state).toBeTruthy();
    return { start, state: state! };
  }
  async function callback(state: string, claims: Record<string, unknown>, cookie: string, user?: object, refreshToken = `refresh-${randomUUID()}`) {
    const code = randomUUID();
    profiles.set(code, { claims, refreshToken });
    // Apple's first form_post is normalized by Better Auth to a GET callback.
    const posted = await form('/api/auth/callback/apple', new URLSearchParams({
      state, code, ...(user ? { user: JSON.stringify(user) } : {}),
    }), cookie);
    const redirected = location(posted);
    expect(redirected.pathname).toBe('/api/auth/callback/apple');
    return call(`${redirected.pathname}${redirected.search}`, {
      headers: { cookie: combineCookies(cookie, cookies(posted)) },
    });
  }
  async function appleCallback(claims: Record<string, unknown>, cookie = '', link = false, user?: object, callbackURL = CALLBACK) {
    const { start, state } = await startApple(cookie, link, callbackURL);
    const response = await callback(state, claims, combineCookies(cookie, cookies(start)), user);
    return { start, response };
  }
  async function signedInCookie(email: string): Promise<string> {
    const otp = await auth.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
    const response = await post('/api/auth/sign-in/email-otp', { email, otp });
    expect(response.status, await response.clone().text()).toBe(200);
    return cookies(response);
  }
  async function stepUp(cookie: string, userId: string): Promise<void> {
    expect((await post('/api/account/step-up/email-otp/send', {}, cookie)).status).toBe(200);
    const session = await prisma.session.findFirstOrThrow({ where: { userId }, orderBy: { createdAt: 'desc' } });
    const verification = await prisma.verification.findFirstOrThrow({
      where: { identifier: { startsWith: `openkey-account-step-up-otp:${session.id}:` } },
    });
    expect((await post('/api/account/step-up/email-otp/verify', { code: verification.value.split(':')[0] }, cookie)).status).toBe(200);
  }
  async function newContinuation(sub: string, email: string) {
    const { response } = await appleCallback(profile(sub, email));
    expect(location(response).searchParams.get('error')).toBe('new_account');
    const continuation = location(response).searchParams.get('continuation');
    expect(continuation).toBeTruthy();
    return { response, continuation: continuation! };
  }
  async function socialOtp(email: string) {
    const otp = await auth.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
    return post('/api/auth/sign-in/email-otp', { email, otp });
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
    // Capture startup cleanup before Better Auth initializes, without waiting a minute.
    globalThis.setInterval = ((handler: (...args: unknown[]) => void, timeout?: number, ...args: unknown[]) => {
      if (timeout === 60_000) sweep = async () => { await handler(...args); };
      return originalSetInterval(handler, timeout, ...args);
    }) as typeof setInterval;
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
    globalThis.setInterval = originalSetInterval;
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
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "user", "verification", "apple_social_continuation" CASCADE');
  });

  if (backend === 'disabled') {
    test('idle disabled startup cleans expired Apple grants without an auth request', async () => {
      await auth.$context;
      const key = (await auth.$context).secretConfig;
      const row = await prisma.appleSocialContinuation.create({ data: {
        id: randomUUID(), identifier: `openkey-apple-confirm:${randomUUID()}`,
        expiresAt: new Date(Date.now() - 1000),
        value: await symmetricEncrypt({ key, data: JSON.stringify({
          providerId: 'apple', bindingHash: 'unused', outcome: 'new_account',
          profile: { id: 'idle-disabled-sub', email: 'idle-disabled@openkey.test', name: '', clientId: SERVICES_ID },
          tokens: { refreshToken: 'idle-disabled-refresh' },
        }) }),
      } });
      expect(sweep).toBeDefined();
      await sweep!();
      expect(revoked).toContainEqual({ token: 'idle-disabled-refresh', clientId: SERVICES_ID });
      expect(await prisma.appleSocialContinuation.count({ where: { id: row.id } })).toBe(0);
      expect(await prisma.user.count()).toBe(0);
      expect(await prisma.session.count()).toBe(0);
    });
    test('credentials alone cannot advertise or start Apple while flag is false', async () => {
      const providers = await call('/api/auth/providers');
      expect(await providers.json()).toEqual({ providers: [] });
      const response = await post('/api/auth/sign-in/social', { provider: 'apple', disableRedirect: true });
      expect(response.status).not.toBe(200);
      expect(await prisma.user.count()).toBe(0);
      expect(await prisma.account.count()).toBe(0);
    });
    test('disabling Apple also refuses an unexpired continuation issued before the flag changed', async () => {
      const continuation = randomUUID();
      const binding = randomUUID();
      const key = (await auth.$context).secretConfig;
      await prisma.appleSocialContinuation.create({ data: {
        id: randomUUID(),
        identifier: `openkey-apple-confirm:${createHash('sha256').update(continuation).digest('base64url')}`,
        expiresAt: new Date(Date.now() + 5 * 60_000),
        value: await symmetricEncrypt({ key, data: JSON.stringify({
          providerId: 'apple', bindingHash: createHash('sha256').update(binding).digest('base64url'), outcome: 'new_account',
          profile: { id: 'prior-apple-sub', email: 'prior@openkey.test', name: 'Prior', clientId: SERVICES_ID },
          tokens: { accessToken: 'stub-access', refreshToken: 'stub-refresh' },
        }) }),
      } });
      const cookie = `__Host-openkey_social_continuation=${binding}`;
      const preview = await call(`/api/auth/social/continuation?continuation=${continuation}`, {
        headers: { cookie },
      });
      expect(preview.status).not.toBe(200);
      const response = await post('/api/auth/social/confirm', { continuation }, cookie);
      expect(response.status).not.toBe(200);
      expect(await prisma.user.count()).toBe(0);
      expect(await prisma.account.count()).toBe(0);
      expect(await prisma.ethereumKey.count()).toBe(0);
      expect(await prisma.session.count()).toBe(0);
      expect(await prisma.appleSocialContinuation.count({ where: {
        identifier: { startsWith: 'openkey-apple-confirm:' },
      } })).toBe(1);
      await prisma.appleSocialContinuation.updateMany({
        where: { identifier: { startsWith: 'openkey-apple-confirm:' } },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      expect((await post('/api/auth/sign-in/email-otp', {
        email: 'unrelated@openkey.test', otp: '000000',
      })).status).toBe(400);
      expect(await prisma.appleSocialContinuation.count()).toBe(1);
      await sweep!();
      expect(revoked).toContainEqual({ token: 'stub-refresh', clientId: SERVICES_ID });
      expect(await prisma.appleSocialContinuation.count()).toBe(0);
    });
    test('disabled Apple preserves the Google-created mailbox email OTP session', async () => {
      const email = 'google-mailbox@openkey.test';
      const user = await prisma.user.create({ data: {
        id: randomUUID(), email, emailVerified: true, socialCreatedProvider: 'google',
      } });
      await prisma.account.create({ data: {
        id: randomUUID(), userId: user.id, providerId: 'google', accountId: 'google-mailbox-sub',
      } });
      const response = await socialOtp(email);
      expect(response.status).toBe(200);
      expect(sessionCookie(response)).toBe(true);
      expect(await prisma.session.count({ where: { userId: user.id } })).toBe(1);
    });
  } else {
    describe('Apple code-flow identity and confirmation', () => {
      test('unsigned form_post user.email cannot claim another mailbox', async () => {
        const victim = await prisma.user.create({ data: { id: randomUUID(), email: 'victim@openkey.test', emailVerified: true } });
        const { response } = await appleCallback(profile('attacker-sub'), '', false, {
          email: victim.email, name: { firstName: 'Attacker' },
        });
        expect(location(response).searchParams.get('error')).toBe('apple_email_required');
        expect(await prisma.user.count()).toBe(1);
        expect(await prisma.account.count()).toBe(0);
        expect(await prisma.ethereumKey.count()).toBe(0);
        expect(await prisma.session.count()).toBe(0);
        expect(sessionCookie(response)).toBe(false);
      });

      test.each([
        ['issuer', { iss: 'https://evil.example' }],
        ['audience', { aud: 'wrong-services-id' }],
        ['expiry', { exp: Math.floor(Date.now() / 1000) - 60 }],
        ['issued-at', { iat: Math.floor(Date.now() / 1000) - 7200 }],
        ['unverified', { email_verified: false }],
      ])('rejects invalid Apple %s claims without creating credentials', async (_name, override) => {
        const { response } = await appleCallback(profile('invalid-sub', 'invalid@openkey.test', override));
        expect(location(response).searchParams.get('error')).not.toBe('new_account');
        expect(location(response).searchParams.has('continuation')).toBe(false);
        expect(sessionCookie(response)).toBe(false);
        expect(await prisma.user.count()).toBe(0);
        expect(await prisma.account.count()).toBe(0);
        expect(await prisma.ethereumKey.count()).toBe(0);
      });

      test('verified Apple form_post requires bound Create, then issues a session and one working sealed key', async () => {
        const email = 'new-apple@openkey.test';
        const { response, continuation } = await newContinuation('new-apple-sub', email);
        expect(response.headers.get('referrer-policy')).toBe('no-referrer');
        expect(await prisma.user.count()).toBe(0);
        expect(await prisma.session.count()).toBe(0);
        expect((await post('/api/auth/social/confirm', { continuation })).status).toBe(400);
        const created = await post('/api/auth/social/confirm', { continuation }, cookies(response));
        expect(created.status, await created.clone().text()).toBe(200);
        expect(sessionCookie(created)).toBe(true);
        const user = await prisma.user.findUniqueOrThrow({ where: { email } });
        expect(user.emailVerified).toBe(true);
        const key = await prisma.ethereumKey.findMany({ where: { userId: user.id, isCanonicalTinyCloud: true } });
        expect(key).toHaveLength(1);
        expect(key[0]!.sealedBlob).toBeTruthy();
        expect(key[0]!.sealingContext).toBeTruthy();
        const account = await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple', accountId: 'new-apple-sub' } });
        expect(account.appleClientId).toBe(SERVICES_ID);
        expect(account.refreshToken).toBeTruthy();
        expect(account.refreshToken).not.toContain('refresh-');
        const session = await call('/api/auth/get-session', { headers: { cookie: cookies(created) } });
        expect((await session.json() as { user: { id: string } }).user.id).toBe(user.id);
        const message = 'TC-1230 canonical Apple account key';
        const signed = await post(`/api/keys/${key[0]!.id}/sign`, { message }, cookies(created));
        expect(signed.status, await signed.clone().text()).toBe(200);
        const { signature, address } = await signed.json() as { signature: `0x${string}`; address: string };
        expect((await recoverMessageAddress({ message, signature })).toLowerCase()).toBe(address.toLowerCase());
        expect(address.toLowerCase()).toBe(key[0]!.address.toLowerCase());
      });

      test('continuation cannot be replayed or redeemed with stolen binding cookie', async () => {
        const first = await newContinuation('binding-a', 'binding-a@openkey.test');
        const second = await newContinuation('binding-b', 'binding-b@openkey.test');
        expect((await post('/api/auth/social/confirm', { continuation: first.continuation }, cookies(second.response))).status).toBe(400);
        expect(await prisma.user.count()).toBe(0);
        expect((await post('/api/auth/social/confirm', { continuation: first.continuation }, cookies(first.response))).status).toBe(200);
        expect((await post('/api/auth/social/confirm', { continuation: first.continuation }, cookies(first.response))).status).toBe(400);
        expect(await prisma.user.count()).toBe(1);
      });

      test('expired continuation cannot create an account and revokes abandoned tokens', async () => {
        const { response, continuation } = await newContinuation('expired-sub', 'expired@openkey.test');
        await prisma.appleSocialContinuation.updateMany({
          where: { identifier: { startsWith: 'openkey-apple-confirm:' } },
          data: { expiresAt: new Date(Date.now() - 1000) },
        });
        expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(400);
        expect(await prisma.user.count()).toBe(0);
        expect(await prisma.account.count()).toBe(0);
        expect(sweep).toBeDefined();
        await sweep!();
        expect(revoked.some(({ token, clientId }) => token.startsWith('refresh-') && clientId === SERVICES_ID)).toBe(true);
      });

      test('native PAR authorize query cannot be changed before confirmation', async () => {
        const callbackURL = `${ORIGIN}/auth/login?tinycloud_request=signed-request&client_id=native-client&native_social_error=1`;
        const { response } = await appleCallback(profile('native-web-sub', 'native-web@openkey.test'), '', false, undefined, callbackURL);
        const target = location(response);
        expect(target.searchParams.get('error')).toBe('new_account');
        const continuation = target.searchParams.get('continuation');
        expect(continuation).toBeTruthy();
        const oauthQuery = new URLSearchParams(target.searchParams);
        oauthQuery.delete('error'); oauthQuery.delete('continuation'); oauthQuery.delete('native_social_error');
        const altered = new URLSearchParams(oauthQuery);
        altered.set('client_id', 'attacker-client');
        expect((await post('/api/auth/social/confirm', { continuation, oauthQuery: altered.toString() }, cookies(response))).status).toBe(400);
        expect(await prisma.user.count()).toBe(0);
        expect((await post('/api/auth/social/confirm', { continuation, oauthQuery: oauthQuery.toString() }, cookies(response))).status).toBe(200);
        expect(await prisma.user.count()).toBe(1);
      });

      test('verified matching email gives account_exists without silent link or retained provider tokens', async () => {
        const email = 'existing@openkey.test';
        const user = await prisma.user.create({ data: { id: randomUUID(), email, emailVerified: true } });
        const { response } = await appleCallback(profile('existing-apple-sub', email));
        const target = location(response);
        expect(target.searchParams.get('error')).toBe('account_exists');
        expect(sessionCookie(response)).toBe(false);
        expect(await prisma.account.count({ where: { userId: user.id } })).toBe(0);
        const continuation = target.searchParams.get('continuation');
        expect(continuation).toBeTruthy();
        const preview = await call(`/api/auth/social/continuation?continuation=${encodeURIComponent(continuation!)}`, {
          headers: { cookie: cookies(response) },
        });
        expect((await preview.json() as { outcome: string }).outcome).toBe('account_exists');
        const rows = await prisma.appleSocialContinuation.findMany({ where: { identifier: { startsWith: 'openkey-apple-confirm:' } } });
        expect(rows).toHaveLength(1);
        const key = (await auth.$context).secretConfig;
        const stored = JSON.parse(await symmetricDecrypt({ key, data: rows[0]!.value })) as Record<string, unknown>;
        expect(stored.outcome).toBe('account_exists');
        expect(stored).not.toHaveProperty('tokens');
        expect(JSON.stringify(stored)).not.toContain('refresh-');
        expect(revoked.some(({ token, clientId }) => token.startsWith('refresh-') && clientId === SERVICES_ID)).toBe(true);
      });

      test('failed existing-email revocation retains encrypted token for expiry retry', async () => {
        const email = 'retry-revoke@openkey.test';
        await prisma.user.create({ data: { id: randomUUID(), email, emailVerified: true } });
        failRevocation = true;
        const { response } = await appleCallback(profile('retry-revoke-sub', email));
        expect(location(response).searchParams.get('error')).toBe('account_exists');
        const row = await prisma.appleSocialContinuation.findFirstOrThrow({
          where: { identifier: { startsWith: 'openkey-apple-confirm:' } },
        });
        const key = (await auth.$context).secretConfig;
        const stored = JSON.parse(await symmetricDecrypt({ key, data: row.value })) as {
          tokens?: { refreshToken?: string };
        };
        expect(stored.tokens?.refreshToken?.startsWith('refresh-')).toBe(true);
        expect(row.value).not.toContain(stored.tokens!.refreshToken!);
        await prisma.appleSocialContinuation.update({ where: { id: row.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
        await sweep!();
        expect(await prisma.appleSocialContinuation.count({ where: { id: row.id } })).toBe(1);
        failRevocation = false;
        await sweep!();
        expect(await prisma.appleSocialContinuation.count({ where: { id: row.id } })).toBe(0);
        expect(revoked).toHaveLength(3);
        expect(await prisma.account.count()).toBe(0);
      });
      test('failed revoke after a Create race retains the abandoned token for retry', async () => {
        const email = 'create-race@openkey.test';
        const { response, continuation } = await newContinuation('create-race-sub', email);
        await prisma.user.create({ data: { id: randomUUID(), email, emailVerified: true } });
        failRevocation = true;
        const rejected = await post('/api/auth/social/confirm', { continuation }, cookies(response));
        expect(rejected.status).toBe(400);
        expect(await prisma.account.count()).toBe(0);
        const row = await prisma.appleSocialContinuation.findFirstOrThrow({
          where: { identifier: { startsWith: 'openkey-apple-confirm:' } },
        });
        const key = (await auth.$context).secretConfig;
        const retained = JSON.parse(await symmetricDecrypt({ key, data: row.value })) as {
          tokens?: { refreshToken?: string };
        };
        expect(retained.tokens?.refreshToken?.startsWith('refresh-')).toBe(true);
        expect(row.value).not.toContain(retained.tokens!.refreshToken!);
        await prisma.appleSocialContinuation.update({ where: { id: row.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
        failRevocation = false;
        await sweep!();
        expect(revoked.some(({ token, clientId }) => token.startsWith('refresh-') && clientId === SERVICES_ID)).toBe(true);
        expect(await prisma.appleSocialContinuation.count({ where: { id: row.id } })).toBe(0);
      });

      test('failed revoke survives unrelated OTP lookup until recovery succeeds', async () => {
        const email = 'retry-survival@openkey.test';
        const { response, continuation } = await newContinuation('retry-survival-sub', email);
        await prisma.user.create({ data: { id: randomUUID(), email, emailVerified: true } });
        failRevocation = true;
        expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(400);
        const job = await prisma.appleSocialContinuation.findFirstOrThrow({
          where: { identifier: { startsWith: 'openkey-apple-confirm:revoke:' } },
        });
        expect(revoked).toHaveLength(1);
        expect((await post('/api/auth/sign-in/email-otp', {
          email: 'unrelated@openkey.test', otp: '000000',
        })).status).toBe(400);
        expect(await prisma.appleSocialContinuation.count({ where: { id: job.id } })).toBe(1);
        failRevocation = false;
        await sweep!();
        expect(revoked).toContainEqual({ token: expect.stringContaining('refresh-'), clientId: SERVICES_ID });
        expect(revoked).toHaveLength(2);
        expect(await prisma.appleSocialContinuation.count({ where: { id: job.id } })).toBe(0);
        expect(await prisma.account.count()).toBe(0);
      });

      test('linked Apple subject is never revoked by an earlier failed existing-email cleanup', async () => {
        const email = 'later-link@openkey.test';
        const user = await prisma.user.create({ data: { id: randomUUID(), email, emailVerified: true } });
        failRevocation = true;
        await appleCallback(profile('later-linked-sub', email));
        const cookie = await signedInCookie(email);
        await stepUp(cookie, user.id);
        await appleCallback(profile('later-linked-sub', email), cookie, true);
        expect(await prisma.account.count({ where: { providerId: 'apple', accountId: 'later-linked-sub' } })).toBe(1);
        await prisma.appleSocialContinuation.updateMany({
          where: { identifier: { startsWith: 'openkey-apple-confirm:' } },
          data: { expiresAt: new Date(Date.now() - 1000) },
        });
        failRevocation = false;
        const before = revoked.length;
        await sweep!();
        expect(revoked).toHaveLength(before);
      });

      test('a subject linked before confirmation is not revoked by its old continuation', async () => {
        const { response, continuation } = await newContinuation('linked-before-create', 'unclaimed@openkey.test');
        const user = await prisma.user.create({ data: {
          id: randomUUID(), email: 'link-owner@openkey.test', emailVerified: true,
        } });
        const cookie = await signedInCookie(user.email);
        await stepUp(cookie, user.id);
        await appleCallback(profile('linked-before-create', user.email), cookie, true);
        const before = revoked.length;
        expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(400);
        expect(revoked).toHaveLength(before);
        expect(await prisma.account.count({ where: { userId: user.id, accountId: 'linked-before-create' } })).toBe(1);
      });

      test('verified relay domain is private without the optional Apple claim', async () => {
        const { response, continuation } = await newContinuation('relay-domain-only', 'domain-only@privaterelay.appleid.com');
        const preview = await call(`/api/auth/social/continuation?continuation=${continuation}`, {
          headers: { cookie: cookies(response) },
        });
        expect((await preview.json() as { isPrivateEmail?: boolean }).isPrivateEmail).toBe(true);

        await prisma.user.create({ data: {
          id: randomUUID(), email: 'existing@privaterelay.appleid.com', emailVerified: true,
        } });
        const existing = await appleCallback(profile('existing-relay-sub', 'existing@privaterelay.appleid.com'));
        expect(location(existing.response).searchParams.get('error')).toBe('account_exists');
        expect(await prisma.account.count()).toBe(0);
      });

      test('identity claimed before Create leaves no orphan user or key', async () => {
        const email = 'conflict@openkey.test';
        const { response, continuation } = await newContinuation('already-owned-sub', email);
        const owner = await prisma.user.create({ data: { id: randomUUID(), email: 'owner@openkey.test', emailVerified: true } });
        await prisma.account.create({ data: { id: randomUUID(), userId: owner.id, providerId: 'apple', accountId: 'already-owned-sub' } });
        expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(400);
        expect(await prisma.user.count({ where: { email } })).toBe(0);
        expect(await prisma.ethereumKey.count()).toBe(0);
        expect(await prisma.account.count({ where: { providerId: 'apple', accountId: 'already-owned-sub' } })).toBe(1);
      });
    });

    describe('explicit Apple linking', () => {
      test('email match cannot link without current-session OTP step-up', async () => {
        const user = await prisma.user.create({ data: { id: randomUUID(), email: 'link@openkey.test', emailVerified: true } });
        const cookie = await signedInCookie(user.email);
        expect((await post('/api/auth/link-social', { provider: 'apple', disableRedirect: true }, cookie)).status).toBe(403);
        const { response } = await appleCallback(profile('silent-sub', user.email));
        expect(location(response).searchParams.get('error')).toBe('account_exists');
        expect(await prisma.account.count({ where: { userId: user.id, providerId: 'apple' } })).toBe(0);
      });

      test.each([
        ['relay', profile('relay-sub', 'random@privaterelay.appleid.com', { is_private_email: 'true', email_verified: 'true' })],
        ['different', profile('different-sub', 'other@openkey.test')],
        ['no-email', profile('no-email-sub')],
      ])('OTP step-up links %s identity without modifying primary email', async (_label, claims) => {
        const user = await prisma.user.create({ data: { id: randomUUID(), email: 'primary@openkey.test', emailVerified: true } });
        const cookie = await signedInCookie(user.email);
        await stepUp(cookie, user.id);
        const sessions = await prisma.session.count({ where: { userId: user.id } });
        const { response } = await appleCallback(claims, cookie, true);
        expect(response.status).toBe(302);
        expect(location(response).searchParams.has('error')).toBe(false);
        expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).email).toBe(user.email);
        expect(await prisma.session.count({ where: { userId: user.id } })).toBe(sessions);
        const account = await prisma.account.findFirstOrThrow({ where: { userId: user.id, providerId: 'apple', accountId: String(claims.sub) } });
        expect(account.appleClientId).toBe(SERVICES_ID);
        expect(account.refreshToken).toBeTruthy();
        expect(account.refreshToken).not.toContain('refresh-');
      });

      test.each(['revoked', 'expired'])('%s originating session cannot write an Apple Account at callback', async (kind) => {
        const user = await prisma.user.create({ data: { id: randomUUID(), email: 'stolen@openkey.test', emailVerified: true } });
        const cookie = await signedInCookie(user.email);
        await stepUp(cookie, user.id);
        const { start, state } = await startApple(cookie, true);
        if (kind === 'revoked') await prisma.session.deleteMany({ where: { userId: user.id } });
        else await prisma.session.updateMany({ where: { userId: user.id }, data: { lastEmailOtpAt: new Date(Date.now() - 6 * 60_000) } });
        await callback(state, profile(`stolen-${kind}`, user.email), combineCookies(cookie, cookies(start)));
        expect(await prisma.account.count({ where: { userId: user.id, providerId: 'apple' } })).toBe(0);
        expect(await prisma.user.count()).toBe(1);
      });

      test('the same Apple sub cannot be linked to a second stepped-up user', async () => {
        const first = await prisma.user.create({ data: { id: randomUUID(), email: 'first@openkey.test', emailVerified: true } });
        const second = await prisma.user.create({ data: { id: randomUUID(), email: 'second@openkey.test', emailVerified: true } });
        const firstCookie = await signedInCookie(first.email);
        await stepUp(firstCookie, first.id);
        await appleCallback(profile('shared-sub', first.email), firstCookie, true);
        const secondCookie = await signedInCookie(second.email);
        await stepUp(secondCookie, second.id);
        const { response } = await appleCallback(profile('shared-sub', second.email), secondCookie, true);
        expect(location(response).searchParams.get('error')).toBe('account_already_linked_to_different_user');
        expect(await prisma.account.count({ where: { providerId: 'apple', accountId: 'shared-sub', userId: first.id } })).toBe(1);
        expect(await prisma.account.count({ where: { userId: second.id } })).toBe(0);
        expect(await prisma.user.count()).toBe(2);
        expect(await prisma.ethereumKey.count()).toBe(0);
      });

      test('Apple unlink requires fresh email OTP and revokes the issuing-client refresh token', async () => {
        const user = await prisma.user.create({ data: { id: randomUUID(), email: 'unlink@openkey.test', emailVerified: true } });
        const cookie = await signedInCookie(user.email);
        await stepUp(cookie, user.id);
        await appleCallback(profile('unlink-sub', 'relay@privaterelay.appleid.com'), cookie, true);
        await prisma.session.updateMany({
          where: { userId: user.id }, data: { lastEmailOtpAt: new Date(Date.now() - 6 * 60_000) },
        });
        expect((await post('/api/account/social/unlink', { providerId: 'apple', accountId: 'unlink-sub' }, cookie)).status).toBe(403);
        expect(await prisma.account.count({ where: { userId: user.id, providerId: 'apple' } })).toBe(1);
        await stepUp(cookie, user.id);
        expect((await post('/api/account/social/unlink', { providerId: 'apple', accountId: 'unlink-sub' }, cookie)).status).toBe(200);
        expect(await prisma.account.count({ where: { userId: user.id, providerId: 'apple' } })).toBe(0);
        expect(revoked.some(({ token, clientId }) => token.startsWith('refresh-') && clientId === SERVICES_ID)).toBe(true);
      });
      test('new Apple sign-in refreshes issuing client ID along with its rotated refresh token', async () => {
        const user = await prisma.user.create({ data: {
          id: randomUUID(), email: 'rotated@openkey.test', emailVerified: true,
        } });
        const cookie = await signedInCookie(user.email);
        await stepUp(cookie, user.id);
        await appleCallback(profile('rotated-sub', user.email), cookie, true);
        const account = await prisma.account.findFirstOrThrow({
          where: { userId: user.id, providerId: 'apple', accountId: 'rotated-sub' },
        });
        await prisma.account.update({ where: { id: account.id }, data: { appleClientId: 'previous-services-id' } });
        const { response } = await appleCallback(profile('rotated-sub', user.email));
        expect(location(response).searchParams.has('error')).toBe(false);
        const refreshed = await prisma.account.findUniqueOrThrow({ where: { id: account.id } });
        expect(refreshed.refreshToken).not.toBe(account.refreshToken);
        expect(refreshed.appleClientId).toBe(SERVICES_ID);
      });

      test('pending Apple confirmation stores the token issuer even when configuration rotates', async () => {
        const email = 'pending-rotation@openkey.test';
        const { response, continuation } = await newContinuation('pending-rotation-sub', email);
        const originalClientId = process.env.APPLE_CLIENT_ID;
        try {
          process.env.APPLE_CLIENT_ID = 'rotated-services-id';
          expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(200);
        } finally {
          if (originalClientId === undefined) delete process.env.APPLE_CLIENT_ID;
          else process.env.APPLE_CLIENT_ID = originalClientId;
        }
        const account = await prisma.account.findFirstOrThrow({
          where: { providerId: 'apple', accountId: 'pending-rotation-sub' },
        });
        expect(account.appleClientId).toBe(SERVICES_ID);
      });

      test('stock Apple unlink cannot bypass revocation; custom unlink uses the issuing client', async () => {
        const user = await prisma.user.create({ data: {
          id: randomUUID(), email: 'stock-unlink@openkey.test', emailVerified: true,
        } });
        const cookie = await signedInCookie(user.email);
        await stepUp(cookie, user.id);
        await appleCallback(profile('stock-unlink-sub', user.email), cookie, true);
        failRevocation = true;
        const stock = await post('/api/auth/unlink-account', {
          providerId: 'apple', accountId: 'stock-unlink-sub',
        }, cookie);
        expect(stock.status).not.toBe(200);
        expect(await prisma.account.count({ where: { userId: user.id, accountId: 'stock-unlink-sub' } })).toBe(1);
        expect((await post('/api/account/social/unlink', {
          providerId: 'apple', accountId: 'stock-unlink-sub',
        }, cookie)).status).toBe(503);
        failRevocation = false;
        expect((await post('/api/account/social/unlink', {
          providerId: 'apple', accountId: 'stock-unlink-sub',
        }, cookie)).status).toBe(200);
        expect(revoked.some(({ token, clientId }) => token.startsWith('refresh-') && clientId === SERVICES_ID)).toBe(true);
        expect(await prisma.account.count({ where: { userId: user.id, accountId: 'stock-unlink-sub' } })).toBe(0);
      });
    });

    describe('social-created mailbox review', () => {
      test('creation sends the mailbox a social sign-up notice', async () => {
        const email = 'notice@openkey.test';
        const { response, continuation } = await newContinuation('notice-sub', email);
        expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(200);
        expect(mail.some((message) => message.to === email && /apple/i.test(`${message.subject} ${message.html}`))).toBe(true);
      });

      test('first email OTP sign-in asks for linked providers before granting a session', async () => {
        const email = 'review@openkey.test';
        const { response, continuation } = await newContinuation('review-sub', email);
        const created = await post('/api/auth/social/confirm', { continuation }, cookies(response));
        expect(created.status).toBe(200);
        await prisma.session.deleteMany({ where: { userId: (await prisma.user.findUniqueOrThrow({ where: { email } })).id } });
        const attempted = await socialOtp(email);
        expect(attempted.status).toBe(403);
        const body = await attempted.json() as { code: string; confirmation: string; providers: string[] };
        expect(body.code).toBe('SOCIAL_ACCOUNT_REVIEW_REQUIRED');
        expect(body.providers).toContain('apple');
        expect(body.confirmation).toBeTruthy();
        expect(sessionCookie(attempted)).toBe(false);
        const accepted = await post('/api/auth/social/email-sign-in/confirm', { confirmation: body.confirmation, decision: 'continue' }, cookies(attempted));
        expect(accepted.status, await accepted.clone().text()).toBe(200);
        expect(sessionCookie(accepted)).toBe(true);
        expect((await post('/api/auth/social/email-sign-in/confirm', { confirmation: body.confirmation, decision: 'continue' }, cookies(attempted))).status).toBe(400);
        const next = await socialOtp(email);
        expect(next.status, await next.clone().text()).toBe(200);
        expect(sessionCookie(next)).toBe(true);
      });

      test('"not mine" locks the social-created account and issues no session', async () => {
        const email = 'refusal@openkey.test';
        const { response, continuation } = await newContinuation('refusal-sub', email);
        const created = await post('/api/auth/social/confirm', { continuation }, cookies(response));
        expect(created.status).toBe(200);
        const user = await prisma.user.findUniqueOrThrow({ where: { email } });
        await prisma.session.deleteMany({ where: { userId: user.id } });
        const attempted = await socialOtp(email);
        expect(attempted.status).toBe(403);
        const body = await attempted.json() as { confirmation: string };
        expect(body.confirmation).toBeTruthy();
        const refused = await post('/api/auth/social/email-sign-in/confirm', { confirmation: body.confirmation, decision: 'not_mine' }, cookies(attempted));
        expect(refused.status).toBe(200);
        expect(sessionCookie(refused)).toBe(false);
        expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).lockedAt).toBeTruthy();
        expect(await prisma.session.count({ where: { userId: user.id } })).toBe(0);
      });
    });
  }
}
