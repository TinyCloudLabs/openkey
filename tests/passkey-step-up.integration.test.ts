import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import type { Server } from 'bun';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { SignJWT } from 'jose';
import type * as DatabaseModule from '@openkey/db';
import type * as AuthModule from '../apps/api/src/auth';

// TC-1198 (plan TC-1188 §2, §3): passkey enrolment and removal need a fresh
// step-up, and only passkeys with enrolment provenance count for step-up.
// Real API, real migrations (with a legacy passkey seeded before the
// provenance migration), real WebAuthn verification against a software
// authenticator, stubbed Apple and Resend.
const backend = process.env.TC1198_PASSKEY_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');
const SERVICES_ID = 'so.openkey.test';
const KID = 'tc1198-key';
const API = 'https://api.openkey.test';
const ORIGIN = 'https://openkey.test';
const RP_ID = 'openkey.test';
const CALLBACK = `${ORIGIN}/auth/social/callback`;
const PROVENANCE_MIGRATION = '20261110_0002_passkey_enrolment_provenance';
const LEGACY_EMAIL = 'legacy@openkey.test';

if (!backend) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  for (const engine of ['pglite', 'postgres']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(`TC-1198 passkey enrolment step-up and provenance (${engine})`, async () => {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: {
          ...process.env,
          TC1198_PASSKEY_TEST_CHILD: engine,
          NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: API,
          BETTER_AUTH_SECRET: 'tc1198-isolated-regression-secret-not-for-production',
          WEBAUTHN_RP_ID: RP_ID, WEBAUTHN_ORIGIN: ORIGIN, CORS_ORIGIN: ORIGIN,
          ADMIN_API_KEY: 'tc1198-admin-key', RESEND_API_KEY: 'tc1198-resend-stub',
          GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
          APPLE_SIGN_IN_ENABLED: 'true', APPLE_NATIVE_SIGN_IN_ENABLED: 'false',
          APPLE_CLIENT_ID: SERVICES_ID, APPLE_TEAM_ID: 'TC1198TEAM',
          APPLE_KEY_ID: KID, APPLE_PRIVATE_KEY: pem, APPLE_WEBHOOK_AUDIENCE: 'so.openkey.test.app',
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
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc1198-'));
  const databaseName = `tc1198_${randomUUID().replaceAll('-', '')}`;
  const { privateKey: appleKey, publicKey: applePublic } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...applePublic.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };
  const originalFetch = globalThis.fetch;
  let httpServer: Server<undefined>;
  let admin: Client | undefined;
  let prisma: DatabaseModule.PrismaClient;
  let auth: typeof AuthModule.auth;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  const profiles = new Map<string, Record<string, unknown>>();
  const mail: Array<{ to: string; subject: string }> = [];

  // ---- A software WebAuthn authenticator (ES256, attestation "none") ----
  type Authenticator = { credentialId: Buffer; privateKey: KeyObject; cose: Buffer; counter: number };
  const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
  const sha256 = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest();
  function cborHead(major: number, length: number): Buffer {
    if (length < 24) return Buffer.from([(major << 5) | length]);
    if (length < 256) return Buffer.from([(major << 5) | 24, length]);
    const out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(length, 1);
    return out;
  }
  function cbor(value: number | string | Uint8Array | Map<number | string, unknown>): Buffer {
    if (typeof value === 'number') return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
    if (typeof value === 'string') return Buffer.concat([cborHead(3, Buffer.byteLength(value)), Buffer.from(value)]);
    if (value instanceof Uint8Array) return Buffer.concat([cborHead(2, value.length), Buffer.from(value)]);
    const parts = [cborHead(5, value.size)];
    for (const [key, entry] of value) parts.push(cbor(key), cbor(entry as never));
    return Buffer.concat(parts);
  }
  function newAuthenticator(): Authenticator {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const key = publicKey.export({ format: 'jwk' });
    const cose = cbor(new Map<number, unknown>([
      [1, 2], [3, -7], [-1, 1],
      [-2, Buffer.from(key.x!, 'base64url')], [-3, Buffer.from(key.y!, 'base64url')],
    ]));
    return { credentialId: randomBytes(16), privateKey, cose, counter: 0 };
  }
  function attestation(authenticator: Authenticator, challenge: string) {
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: ORIGIN, crossOrigin: false }));
    const length = Buffer.alloc(2);
    length.writeUInt16BE(authenticator.credentialId.length);
    const authData = Buffer.concat([
      sha256(RP_ID), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), length, authenticator.credentialId, authenticator.cose,
    ]);
    const attestationObject = cbor(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    return {
      id: b64u(authenticator.credentialId), rawId: b64u(authenticator.credentialId), type: 'public-key',
      response: { clientDataJSON: b64u(clientData), attestationObject: b64u(attestationObject), transports: ['internal'] },
      clientExtensionResults: {}, authenticatorAttachment: 'platform',
    };
  }
  function assertion(authenticator: Authenticator, challenge: string, userVerified = true) {
    authenticator.counter += 1;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(authenticator.counter);
    const authData = Buffer.concat([sha256(RP_ID), Buffer.from([userVerified ? 0x05 : 0x01]), counter]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false }));
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientData)]), authenticator.privateKey);
    return {
      id: b64u(authenticator.credentialId), rawId: b64u(authenticator.credentialId), type: 'public-key',
      response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(signature) },
      clientExtensionResults: {}, authenticatorAttachment: 'platform',
    };
  }
  const legacyAuthenticator = newAuthenticator();

  // ---- HTTP helpers ----
  function cookies(response: Response): string {
    return response.headers.getSetCookie().map((cookie) => cookie.split(';')[0]).join('; ');
  }
  function combine(...parts: string[]): string {
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
  function get(path: string, cookie = '') {
    return call(path, { headers: { origin: ORIGIN, cookie } });
  }
  async function typed(response: Response): Promise<{ status: number; code?: string; methods?: string[] }> {
    const body = await response.json().catch(() => ({})) as { code?: string; methods?: string[] };
    return { status: response.status, code: body.code, methods: body.methods };
  }
  const STEP_UP_REQUIRED = 'PASSKEY_STEP_UP_REQUIRED';

  // ---- Sign-in paths ----
  function location(response: Response): URL {
    const target = response.headers.get('location');
    expect(target).toBeTruthy();
    return new URL(target!);
  }
  async function appleCallback(sub: string, email: string) {
    const start = await post('/api/auth/sign-in/social', {
      provider: 'apple', callbackURL: CALLBACK, errorCallbackURL: CALLBACK, disableRedirect: true,
    });
    expect(start.status, await start.clone().text()).toBe(200);
    const state = new URL((await start.json() as { url: string }).url).searchParams.get('state')!;
    const code = randomUUID();
    const now = Math.floor(Date.now() / 1000);
    profiles.set(code, { iss: 'https://appleid.apple.com', aud: SERVICES_ID, sub, iat: now, exp: now + 3600, email, email_verified: true });
    const posted = await call('/api/auth/callback/apple', {
      method: 'POST', headers: { origin: 'https://appleid.apple.com', 'content-type': 'application/x-www-form-urlencoded', cookie: cookies(start) },
      body: new URLSearchParams({ state, code }).toString(),
    });
    const redirected = location(posted);
    return call(`${redirected.pathname}${redirected.search}`, { headers: { cookie: combine(cookies(start), cookies(posted)) } });
  }
  /** An Apple-created account, then a returning Apple sign-in: a session with no step-up of any kind. */
  async function appleUserWithPlainSession(sub: string, email: string) {
    const first = await appleCallback(sub, email);
    expect(location(first).searchParams.get('error')).toBe('new_account');
    const created = await post('/api/auth/social/confirm', { continuation: location(first).searchParams.get('continuation') }, cookies(first));
    expect(created.status, await created.clone().text()).toBe(200);
    const returning = await appleCallback(sub, email);
    expect(location(returning).searchParams.has('error')).toBe(false);
    const user = await prisma.user.findUniqueOrThrow({ where: { email } });
    return { user, creationCookie: cookies(created), cookie: cookies(returning) };
  }
  /** A session created by a verified email code, through the R9 review for a social-created account. */
  async function emailSignIn(email: string): Promise<string> {
    const otp = await auth.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
    const response = await post('/api/auth/sign-in/email-otp', { email, otp });
    if (response.status === 403) {
      const { code, confirmation } = await response.json() as { code: string; confirmation: string };
      expect(code).toBe('SOCIAL_ACCOUNT_REVIEW_REQUIRED');
      const confirmed = await post('/api/auth/social/email-sign-in/confirm', { confirmation, decision: 'continue' }, cookies(response));
      expect(confirmed.status, await confirmed.clone().text()).toBe(200);
      return cookies(confirmed);
    }
    expect(response.status, await response.clone().text()).toBe(200);
    return cookies(response);
  }
  async function emailSignUp(email: string) {
    const otp = await auth.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
    const refused = await post('/api/auth/sign-in/email-otp', { email, otp });
    const { signupToken } = await refused.json() as { signupToken: string };
    const created = await post('/api/auth/sign-up/email-otp', { email, signupToken });
    expect(created.status, await created.clone().text()).toBe(200);
    return { user: await prisma.user.findUniqueOrThrow({ where: { email } }), cookie: cookies(created) };
  }
  async function sessionId(cookie: string): Promise<string> {
    const response = await get('/api/auth/get-session', cookie);
    return (await response.json() as { session: { id: string } }).session.id;
  }
  async function emailStepUp(cookie: string, purpose: 'link' | 'delete_account' | 'passkey_register' | 'passkey_remove') {
    const send = await post('/api/account/step-up/email-otp/send', { purpose }, cookie);
    if (send.status !== 200) return send;
    const id = await sessionId(cookie);
    const prefix = { link: 'openkey-account-step-up-otp', delete_account: 'openkey-account-delete-otp',
      passkey_register: 'openkey-passkey-register-otp', passkey_remove: 'openkey-passkey-remove-otp' }[purpose];
    const row = await prisma.verification.findFirstOrThrow({ where: { identifier: { startsWith: `${prefix}:${id}:` } } });
    return post('/api/account/step-up/email-otp/verify', { code: row.value.split(':')[0], purpose }, cookie);
  }

  // ---- Passkey ceremonies ----
  async function registerOptions(cookie: string) {
    return get('/api/auth/passkey/generate-register-options', cookie);
  }
  async function enrol(cookie: string, authenticator = newAuthenticator()) {
    const options = await registerOptions(cookie);
    if (options.status !== 200) return { response: options, authenticator };
    const { challenge } = await options.json() as { challenge: string };
    const response = await post('/api/auth/passkey/verify-registration', {
      response: attestation(authenticator, challenge), name: 'test passkey',
    }, combine(cookie, cookies(options)));
    return { response, authenticator };
  }
  async function enrolled(cookie: string, authenticator = newAuthenticator()) {
    const { response } = await enrol(cookie, authenticator);
    expect(response.status, await response.clone().text()).toBe(200);
    const row = await prisma.passkey.findUniqueOrThrow({ where: { credentialID: b64u(authenticator.credentialId) } });
    return { authenticator, passkey: row };
  }
  /** Stock Better Auth passkey sign-in: a new cookie session. */
  async function passkeySignIn(authenticator: Authenticator): Promise<Response> {
    const options = await get('/api/auth/passkey/generate-authenticate-options');
    const { challenge } = await options.json() as { challenge: string };
    return post('/api/auth/passkey/verify-authentication', { response: assertion(authenticator, challenge) }, cookies(options));
  }
  /** The embed proxy's passkey sign-in, the one path that stamps passkey freshness on its new session. */
  async function proxyPasskeySignIn(authenticator: Authenticator) {
    const options = await post('/api/passkey/generate-authenticate-options', {});
    const { challenge, challengeToken } = await options.json() as { challenge: string; challengeToken: string };
    const verified = await post('/api/passkey/verify-authentication', { response: assertion(authenticator, challenge), challengeToken });
    expect(verified.status, await verified.clone().text()).toBe(200);
    return await verified.json() as { session: { id: string } };
  }
  async function sessionStepUp(cookie: string, authenticator: Authenticator, userVerified = true) {
    const options = await post('/api/account/step-up/passkey/options', {}, cookie);
    if (options.status !== 200) return options;
    const { challengeToken, options: request } = await options.json() as { challengeToken: string; options: { challenge: string } };
    return post('/api/account/step-up/passkey/verify', {
      challengeToken, response: assertion(authenticator, request.challenge, userVerified),
    }, cookie);
  }
  const deleteAccount = (cookie: string) => post('/api/account/delete', { confirmation: 'DELETE MY ACCOUNT' }, cookie);
  const deletePasskey = (cookie: string, id: string) => post('/api/auth/passkey/delete-passkey', { id }, cookie);

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    const split = migrations.indexOf(PROVENANCE_MIGRATION);
    expect(split).toBeGreaterThan(0);
    const sql = (name: string) => readFile(join(root, 'packages/db/prisma/migrations', name, 'migration.sql'), 'utf8');
    // A user and passkey enrolled before TC-1198, through the stock route.
    const seed = `
      INSERT INTO "user" (id, email, "emailVerified", "updatedAt") VALUES ('legacy-user', '${LEGACY_EMAIL}', true, now());
      INSERT INTO "passkey" (id, "userId", "publicKey", "credentialID", counter, "deviceType", "backedUp", transports)
        VALUES ('legacy-passkey', 'legacy-user', '${legacyAuthenticator.cose.toString('base64')}',
                '${b64u(legacyAuthenticator.credentialId)}', 0, 'singleDevice', false, 'internal');`;
    let connectionString: string;
    if (backend === 'postgres') {
      if (!postgresUrl) throw new Error('OPENKEY_TEST_POSTGRES_URL is required');
      admin = new Client({ connectionString: postgresUrl });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${databaseName}"`);
      const target = new URL(postgresUrl);
      target.pathname = `/${databaseName}`;
      connectionString = target.toString();
      const connection = new Client({ connectionString });
      await connection.connect();
      try {
        for (const migration of migrations.slice(0, split)) await connection.query(await sql(migration));
        await connection.query(seed);
        for (const migration of migrations.slice(split)) await connection.query(await sql(migration));
      } finally { await connection.end(); }
    } else {
      const database = new PGlite(directory);
      try {
        for (const migration of migrations.slice(0, split)) await database.exec(await sql(migration));
        await database.exec(seed);
        for (const migration of migrations.slice(split)) await database.exec(await sql(migration));
      } finally { await database.close(); }
      connectionString = `pglite:${directory}`;
    }
    process.env.DATABASE_URL = connectionString;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === 'https://appleid.apple.com/auth/token') {
        const code = new URLSearchParams(String(init?.body)).get('code') ?? '';
        const claims = profiles.get(code);
        if (!claims) return Response.json({ error: 'invalid_grant' }, { status: 400 });
        profiles.delete(code);
        const idToken = await new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: KID }).sign(appleKey);
        return Response.json({ access_token: `access-${code}`, refresh_token: `refresh-${code}`, token_type: 'Bearer', expires_in: 3600, id_token: idToken });
      }
      if (url === 'https://appleid.apple.com/auth/keys') return Response.json({ keys: [jwk] });
      if (url === 'https://appleid.apple.com/auth/revoke') return new Response('', { status: 200 });
      if (url.startsWith('https://appleid.apple.com/')) throw new Error(`Unexpected Apple network request: ${url}`);
      if (url.startsWith('https://api.resend.com/')) {
        const body = JSON.parse(String(init?.body ?? '{}')) as { to?: string | string[]; subject?: string };
        mail.push({ to: Array.isArray(body.to) ? body.to[0]! : body.to ?? '', subject: body.subject ?? '' });
        return Response.json({ id: randomUUID() });
      }
      return originalFetch(input, init);
    }) as typeof fetch;
    // Loaded only now: the API and its Prisma client read DATABASE_URL at import time.
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

  beforeEach(() => {
    profiles.clear();
    mail.length = 0;
  });

  describe('existing passkeys (migration backfill)', () => {
    test('a passkey enrolled before the change counts for step-up and still signs in', async () => {
      const legacy = await prisma.passkey.findUniqueOrThrow({ where: { id: 'legacy-passkey' } });
      expect(legacy.countsForStepUp).toBe(true);
      expect(legacy.enrolledVia).toBe('legacy');
      const signedIn = await passkeySignIn(legacyAuthenticator);
      expect(signedIn.status, await signedIn.clone().text()).toBe(200);
      const cookie = cookies(signedIn);
      // The owner's status quo: that passkey confirms deletion.
      expect((await deleteAccount(cookie)).status).toBe(403);
      expect((await sessionStepUp(cookie, legacyAuthenticator)).status).toBe(200);
      const deleted = await deleteAccount(cookie);
      expect(deleted.status, await deleted.clone().text()).toBe(200);
      expect(await prisma.user.count({ where: { email: LEGACY_EMAIL } })).toBe(0);
    });
  });

  describe('session-only calls', () => {
    test('register options, verify-registration, the embed proxy and delete-passkey answer 403 with a typed code', async () => {
      const { user, creationCookie, cookie } = await appleUserWithPlainSession('plain-sub', 'plain@openkey.test');
      // Account creation enrolled the first passkey; the returning session has no step-up.
      const { passkey } = await enrolled(creationCookie);
      expect(passkey.enrolledVia).toBe('account_creation');
      expect(passkey.countsForStepUp).toBe(true);

      expect(await typed(await registerOptions(cookie))).toEqual({ status: 403, code: STEP_UP_REQUIRED, methods: ['passkey', 'email'] });
      const verify = await post('/api/auth/passkey/verify-registration', { response: attestation(newAuthenticator(), 'x') }, cookie);
      expect(await typed(verify)).toMatchObject({ status: 403, code: STEP_UP_REQUIRED });
      const token = (await (await get('/api/auth/get-session', cookie)).json() as { session: { token: string } }).session.token;
      const proxied = await post('/api/passkey/generate-register-options', {}, '', { authorization: `Bearer ${token}` });
      expect(await typed(proxied)).toMatchObject({ status: 403, code: STEP_UP_REQUIRED });
      expect(await typed(await deletePasskey(cookie, passkey.id))).toEqual({ status: 403, code: STEP_UP_REQUIRED, methods: ['passkey'] });
      expect(await prisma.passkey.count({ where: { userId: user.id } })).toBe(1);
    });
  });

  describe('enrol P → sign in with P → delete the account / link Apple (plan §2)', () => {
    test('is rejected without the owner\'s passkey or an email code', async () => {
      const { user, creationCookie, cookie: plain } = await appleUserWithPlainSession('attack-sub', 'attack@openkey.test');
      const { authenticator: owner } = await enrolled(creationCookie);
      // A session holder without a step-up cannot enrol at all.
      expect((await enrol(plain)).response.status).toBe(403);

      // A mailbox holder can enrol (email sign-in is a fresh email proof), but
      // the owner already has a passkey that counts, so the new one does not.
      const mailbox = await emailSignIn(user.email);
      const { authenticator: attacker, passkey: p } = await enrolled(mailbox);
      expect(p.enrolledVia).toBe('email_sign_in');
      expect(p.countsForStepUp).toBe(false);

      // Sign in with P through the path that records passkey freshness.
      const signedIn = await proxyPasskeySignIn(attacker);
      const stamped = await prisma.session.findUniqueOrThrow({ where: { id: signedIn.session.id } });
      expect(stamped.lastPasskeyId).toBe(p.id);
      expect(stamped.lastPasskeyAt).not.toBeNull();
      // Carry that freshness onto the attacker's cookie session.
      const attackerCookie = await emailSignIn(user.email);
      await prisma.session.update({
        where: { id: await sessionId(attackerCookie) },
        data: { lastPasskeyAt: stamped.lastPasskeyAt, lastPasskeyId: stamped.lastPasskeyId },
      });
      expect(await typed(await deleteAccount(attackerCookie))).toMatchObject({ status: 403, code: 'passkey_step_up_required' });
      expect(await typed(await post('/api/account/step-up/email-otp/send', { purpose: 'delete_account' }, attackerCookie)))
        .toMatchObject({ status: 403, code: 'passkey_step_up_required' });
      expect(await typed(await sessionStepUp(attackerCookie, attacker))).toMatchObject({ status: 403, code: 'passkey_not_step_up_capable' });
      const link = await post('/api/auth/link-social', { provider: 'apple', callbackURL: CALLBACK, disableRedirect: true }, attackerCookie);
      expect(await typed(link)).toMatchObject({ status: 403, code: 'EMAIL_STEP_UP_REQUIRED' });
      // Nor can a removal code strip the owner's passkey so a mailbox deletion applies.
      const owners = await prisma.passkey.findFirstOrThrow({ where: { userId: user.id, countsForStepUp: true } });
      expect((await emailStepUp(attackerCookie, 'passkey_remove')).status).toBe(200);
      expect(await typed(await deletePasskey(attackerCookie, owners.id))).toEqual({ status: 403, code: STEP_UP_REQUIRED, methods: ['passkey'] });
      expect(await prisma.user.count({ where: { id: user.id } })).toBe(1);

      // The owner's own passkey still confirms deletion.
      const ownerCookie = cookies(await passkeySignIn(owner));
      expect((await sessionStepUp(ownerCookie, owner)).status).toBe(200);
      expect((await deleteAccount(ownerCookie)).status).toBe(200);
    });

    test('a passkey written without provenance (a stock Better Auth write) never counts', async () => {
      const { user, cookie } = await emailSignUp('stock-write@openkey.test');
      const authenticator = newAuthenticator();
      await prisma.passkey.create({ data: {
        id: randomUUID(), userId: user.id, publicKey: authenticator.cose.toString('base64'),
        credentialID: b64u(authenticator.credentialId), deviceType: 'singleDevice', backedUp: false, transports: 'internal',
      } });
      expect((await passkeySignIn(authenticator)).status).toBe(200);
      expect(await typed(await sessionStepUp(cookie, authenticator))).toMatchObject({ status: 403, code: 'passkey_step_up_required' });
      // With no passkey that counts, the user is treated as passkey-less for deletion (D6).
      expect((await emailStepUp(cookie, 'delete_account')).status).toBe(200);
      expect((await deleteAccount(cookie)).status).toBe(200);
    });
  });

  describe('enrolment under step-up', () => {
    test('a fresh passkey_register code enrols once and records provenance', async () => {
      const { user, cookie } = await appleUserWithPlainSession('otp-sub', 'otp@openkey.test');
      // A linking code is another purpose and authorizes nothing here.
      expect((await emailStepUp(cookie, 'link')).status).toBe(200);
      expect((await registerOptions(cookie)).status).toBe(403);
      const verified = await emailStepUp(cookie, 'passkey_register');
      expect(verified.status, await verified.clone().text()).toBe(200);
      expect(mail.some((message) => message.to === user.email && /add a passkey/i.test(message.subject))).toBe(true);
      const before = Date.now();
      const { passkey } = await enrolled(cookie);
      expect(passkey.enrolledVia).toBe('email_step_up');
      expect(passkey.countsForStepUp).toBe(true);
      expect(passkey.enrolledStepUpAt!.getTime()).toBeGreaterThanOrEqual(before - 1000);
      // Single use.
      expect((await enrol(cookie)).response.status).toBe(403);
    });

    test('a fresh assertion by a passkey that counts authorizes enrolment', async () => {
      const { creationCookie, cookie } = await appleUserWithPlainSession('assert-sub', 'assert@openkey.test');
      const { authenticator } = await enrolled(creationCookie);
      expect((await sessionStepUp(cookie, authenticator)).status).toBe(200);
      const { passkey } = await enrolled(cookie);
      expect(passkey.enrolledVia).toBe('passkey_step_up');
      expect(passkey.countsForStepUp).toBe(true);
    });

    test('sessions created by an email code carry a single-use, five-minute grant', async () => {
      const { user, cookie } = await emailSignUp('signup@openkey.test');
      const { passkey } = await enrolled(cookie);
      expect(passkey.enrolledVia).toBe('account_creation');
      expect(passkey.countsForStepUp).toBe(true);
      expect((await enrol(cookie)).response.status).toBe(403);

      const signIn = await emailSignIn(user.email);
      await prisma.verification.updateMany({
        where: { identifier: `openkey-passkey-register-step-up:${await sessionId(signIn)}` },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      expect(await typed(await registerOptions(signIn))).toMatchObject({ status: 403, code: STEP_UP_REQUIRED });
    });

    test('one grant cannot enrol two passkeys through concurrent ceremonies', async () => {
      const { user, cookie } = await appleUserWithPlainSession('race-sub', 'race@openkey.test');
      expect((await emailStepUp(cookie, 'passkey_register')).status).toBe(200);
      const first = await registerOptions(cookie);
      const second = await registerOptions(cookie);
      expect([first.status, second.status]).toEqual([200, 200]);
      const [a, b] = [newAuthenticator(), newAuthenticator()];
      const { challenge: c1 } = await first.json() as { challenge: string };
      const { challenge: c2 } = await second.json() as { challenge: string };
      const won = await post('/api/auth/passkey/verify-registration', { response: attestation(a, c1) }, combine(cookie, cookies(first)));
      expect(won.status, await won.clone().text()).toBe(200);
      const lost = await post('/api/auth/passkey/verify-registration', { response: attestation(b, c2) }, combine(cookie, cookies(second)));
      expect(await typed(lost)).toMatchObject({ status: 403, code: STEP_UP_REQUIRED });
      expect(await prisma.passkey.findMany({ where: { userId: user.id }, select: { credentialID: true } }))
        .toEqual([{ credentialID: b64u(a.credentialId) }]);
    });
  });

  describe('removal under step-up', () => {
    test('a removal code removes a passkey that does not count; a counting one needs a passkey', async () => {
      const { user, creationCookie, cookie } = await appleUserWithPlainSession('remove-sub', 'remove@openkey.test');
      const { authenticator: owner, passkey: counting } = await enrolled(creationCookie);
      const { passkey: extra } = await enrolled(await emailSignIn(user.email));
      expect(extra.countsForStepUp).toBe(false);

      expect(await typed(await deletePasskey(cookie, extra.id))).toEqual({ status: 403, code: STEP_UP_REQUIRED, methods: ['passkey', 'email'] });
      expect((await emailStepUp(cookie, 'passkey_remove')).status).toBe(200);
      expect(mail.some((message) => /remove a passkey/i.test(message.subject))).toBe(true);
      expect((await deletePasskey(cookie, extra.id)).status).toBe(200);
      expect(await prisma.passkey.count({ where: { id: extra.id } })).toBe(0);
      // The code was single use, and is never offered for a counting passkey.
      expect((await deletePasskey(cookie, counting.id)).status).toBe(403);
      expect(await typed(await post('/api/account/step-up/email-otp/send', { purpose: 'passkey_remove' }, cookie)))
        .toMatchObject({ status: 403, code: 'passkey_step_up_required' });

      expect((await sessionStepUp(cookie, owner)).status).toBe(200);
      expect((await deletePasskey(cookie, counting.id)).status).toBe(200);
      expect(await prisma.passkey.count({ where: { userId: user.id } })).toBe(0);
    });
  });

  describe('the typed refusal lists only methods that can work', () => {
    test('no email method while Apple reports the relay address undeliverable', async () => {
      const email = 'relay-step-up@privaterelay.appleid.com';
      const { user, creationCookie, cookie } = await appleUserWithPlainSession('relay-step-up-sub', email);
      await prisma.account.updateMany({ where: { userId: user.id, providerId: 'apple' }, data: { appleEmailUndeliverable: true } });
      expect(await typed(await registerOptions(cookie))).toEqual({ status: 403, code: STEP_UP_REQUIRED, methods: [] });
      const { passkey } = await enrolled(creationCookie);
      expect(await typed(await registerOptions(cookie))).toEqual({ status: 403, code: STEP_UP_REQUIRED, methods: ['passkey'] });
      expect(await typed(await deletePasskey(cookie, passkey.id))).toEqual({ status: 403, code: STEP_UP_REQUIRED, methods: ['passkey'] });
    });

    test('a proof that lapses mid-ceremony offers the passkey too, and the new credential is gone', async () => {
      const { user, creationCookie, cookie } = await appleUserWithPlainSession('lapse-sub', 'lapse@openkey.test');
      const { authenticator } = await enrolled(creationCookie);
      expect((await sessionStepUp(cookie, authenticator)).status).toBe(200);
      const options = await registerOptions(cookie);
      expect(options.status).toBe(200);
      const { challenge } = await options.json() as { challenge: string };
      await prisma.session.update({ where: { id: await sessionId(cookie) }, data: { lastPasskeyAt: new Date(Date.now() - 301_000) } });
      const late = newAuthenticator();
      const refused = await post('/api/auth/passkey/verify-registration', { response: attestation(late, challenge) }, combine(cookie, cookies(options)));
      expect(await typed(refused)).toEqual({ status: 403, code: STEP_UP_REQUIRED, methods: ['passkey', 'email'] });
      expect(await prisma.passkey.count({ where: { userId: user.id, credentialID: b64u(late.credentialId) } })).toBe(0);
    });

    test('a session past Better Auth\'s fresh age gets Better Auth\'s own refusal, with no step-up asked for', async () => {
      const { cookie } = await appleUserWithPlainSession('stale-session-sub', 'stale-session@openkey.test');
      await prisma.session.update({ where: { id: await sessionId(cookie) }, data: { createdAt: new Date(Date.now() - 2 * 86_400_000) } });
      expect(await typed(await registerOptions(cookie))).toMatchObject({ status: 403, code: 'SESSION_NOT_FRESH' });
    });
  });

  describe('session passkey step-up', () => {
    test('needs user verification, a counting passkey and a single-use challenge bound to this session', async () => {
      const { creationCookie, cookie } = await appleUserWithPlainSession('bind-sub', 'bind@openkey.test');
      const { authenticator } = await enrolled(creationCookie);
      expect((await sessionStepUp(cookie, authenticator, false)).status).toBe(400);

      const options = await post('/api/account/step-up/passkey/options', {}, cookie);
      const { challengeToken, options: request } = await options.json() as { challengeToken: string; options: { challenge: string; allowCredentials: Array<{ id: string }>; userVerification: string } };
      expect(request.userVerification).toBe('required');
      expect(request.allowCredentials.map(({ id }) => id)).toEqual([b64u(authenticator.credentialId)]);
      const response = assertion(authenticator, request.challenge);
      // Another session of the same user cannot spend this session's challenge.
      expect((await post('/api/account/step-up/passkey/verify', { challengeToken, response }, creationCookie)).status).toBe(400);
      expect((await post('/api/account/step-up/passkey/verify', { challengeToken, response }, cookie)).status).toBe(200);
      expect((await post('/api/account/step-up/passkey/verify', { challengeToken, response }, cookie)).status).toBe(400);
      const stamped = await prisma.session.findUniqueOrThrow({ where: { id: await sessionId(cookie) } });
      expect(stamped.lastPasskeyId).not.toBeNull();

      const info = await get('/api/account', cookie);
      expect((await info.json() as { user: { stepUpPasskeys: number } }).user.stepUpPasskeys).toBe(1);
    });

    test('a bearer token cannot step up', async () => {
      const { cookie } = await appleUserWithPlainSession('bearer-sub', 'bearer@openkey.test');
      const token = (await (await get('/api/auth/get-session', cookie)).json() as { session: { token: string } }).session.token;
      expect((await post('/api/account/step-up/passkey/options', {}, '', { authorization: `Bearer ${token}` })).status).toBe(403);
    });
  });
}
