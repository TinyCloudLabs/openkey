import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import type * as DatabaseModule from '@openkey/db';
import type * as AuthModule from '../apps/api/src/auth';

const backend = process.env.TC1197_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');

if (!backend) {
  for (const engine of ['pglite', 'postgres']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(`TC-1197 Google linking and confirmation (${engine})`, async () => {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: {
          ...process.env,
          TC1197_TEST_CHILD: engine,
          NODE_ENV: 'test',
          TEE_MODE: 'development',
          BETTER_AUTH_URL: 'https://api.openkey.test',
          BETTER_AUTH_SECRET: 'tc1197-isolated-regression-secret-not-for-production',
          WEBAUTHN_RP_ID: 'openkey.test',
          WEBAUTHN_ORIGIN: 'https://openkey.test',
          CORS_ORIGIN: 'https://openkey.test',
          ADMIN_API_KEY: 'tc1197-admin-key',
          APPLE_SIGN_IN_ENABLED: 'false',
          RESEND_API_KEY: '',
          GOOGLE_CLIENT_ID: 'tc1197-google-client',
          GOOGLE_CLIENT_SECRET: 'tc1197-google-secret',
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
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc1197-'));
  const databaseName = `tc1197_${randomUUID().replaceAll('-', '')}`;
  let admin: Client | undefined;
  let prisma: DatabaseModule.PrismaClient;
  let auth: typeof AuthModule.auth;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  const API = 'https://api.openkey.test';
  const ORIGIN = 'https://openkey.test';
  const originalFetch = globalThis.fetch;
  const profiles = new Map<string, { sub: string; email: string; email_verified: boolean }>();

  function jwt(payload: object): string {
    return `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.signature`;
  }
  function cookies(response: Response): string {
    return response.headers.getSetCookie().map((cookie) => cookie.split(';')[0]).join('; ');
  }
  function call(path: string, init: RequestInit = {}) {
    return app.fetch(new Request(`${API}${path}`, init));
  }
  function post(path: string, body: unknown, cookie = '') {
    return call(path, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json', cookie },
      body: JSON.stringify(body),
    });
  }
  async function signedInCookie(email: string): Promise<string> {
    const otp = await auth.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
    const response = await post('/api/auth/sign-in/email-otp', { email, otp });
    expect(response.status).toBe(200);
    return cookies(response);
  }
  async function stepUp(cookie: string, userId: string): Promise<void> {
    const sent = await post('/api/account/step-up/email-otp/send', {}, cookie);
    expect(sent.status).toBe(200);
    const session = await prisma.session.findFirstOrThrow({ where: { userId }, orderBy: { createdAt: 'desc' } });
    const verification = await prisma.verification.findFirstOrThrow({
      where: { identifier: { startsWith: `openkey-account-step-up-otp:${session.id}:` } },
    });
    const code = verification.value.split(':')[0];
    const verified = await post('/api/account/step-up/email-otp/verify', { code }, cookie);
    expect(verified.status).toBe(200);
  }
  async function googleCallback(profile: { sub: string; email: string; email_verified: boolean }, cookie = '', link = false, requestSignUp = false) {
    const callback = `${ORIGIN}/auth/social/callback`;
    const start = await post(link ? '/api/auth/link-social' : '/api/auth/sign-in/social', {
      provider: 'google', callbackURL: callback, errorCallbackURL: callback, disableRedirect: true, requestSignUp,
    }, cookie);
    const body = await start.json() as { url?: string };
    if (!body.url) return { start, response: start };
    const state = new URL(body.url).searchParams.get('state');
    expect(state).toBeTruthy();
    const code = randomUUID();
    profiles.set(code, profile);
    const response = await call(`/api/auth/callback/google?state=${encodeURIComponent(state!)}&code=${code}`, {
      headers: { cookie: [cookie, cookies(start)].filter(Boolean).join('; ') },
    });
    return { start, response };
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
      if (url === 'https://oauth2.googleapis.com/token') {
        const code = new URLSearchParams(String(init?.body)).get('code');
        const profile = profiles.get(code ?? '');
        if (!profile) return new Response('{}', { status: 400 });
        profiles.delete(code!);
        return Response.json({
          access_token: 'test-google-access-token', token_type: 'Bearer', expires_in: 3600,
          id_token: jwt(profile),
        });
      }
      if (url.startsWith('https://oauth2.googleapis.com/revoke')) return new Response('', { status: 200 });
      return originalFetch(input, init);
    }) as typeof fetch;
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    ({ auth } = await import('../apps/api/src/auth'));
    app = (await import('../apps/api/src/index')).default;
  }, 120_000);

  afterAll(async () => {
    globalThis.fetch = originalFetch;
    await prisma?.$disconnect();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await admin.end();
    }
    await rm(directory, { recursive: true, force: true });
  });
  beforeEach(async () => {
    profiles.clear();
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "user", "verification" CASCADE');
  });

  describe('Google sign-in boundaries', () => {
    test('unverified Google email creates no user or session', async () => {
      const { response } = await googleCallback({ sub: 'unverified-sub', email: 'unverified@openkey.test', email_verified: false });
      expect(await prisma.user.count()).toBe(0);
      expect(cookies(response)).not.toContain('session_token=');
      expect(new URL(response.headers.get('location')!).searchParams.has('continuation')).toBe(false);
    });

    test('matching verified email never links without an explicit step-up', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'existing@openkey.test', emailVerified: true } });
      const { response } = await googleCallback({ sub: 'matching-sub', email: user.email, email_verified: true });
      expect(await prisma.account.count({ where: { userId: user.id, providerId: 'google' } })).toBe(0);
      expect(new URL(response.headers.get('location')!).searchParams.get('error')).toBe('account_exists');
      expect(cookies(response)).not.toContain('session_token=');
      const url = new URL(response.headers.get('location')!);
      expect(url.searchParams.has('continuation')).toBe(true);
      const preview = await call(`/api/auth/social/continuation?continuation=${url.searchParams.get('continuation')}`, {
        headers: { cookie: cookies(response) },
      });
      expect((await preview.json() as { outcome: string }).outcome).toBe('account_exists');
      expect(await prisma.account.count()).toBe(0);
    });

    test('a matching verified email with different casing remains an existing account', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'ExistingCase@openkey.test', emailVerified: true } });
      const { response } = await googleCallback({ sub: 'case-sub', email: 'existingcase@openkey.test', email_verified: true });
      expect(new URL(response.headers.get('location')!).searchParams.get('error')).toBe('account_exists');
      expect(await prisma.account.count({ where: { userId: user.id } })).toBe(0);
      expect(await prisma.user.count()).toBe(1);
    });

    test('literal email punctuation does not match another account', async () => {
      await prisma.user.create({ data: { id: randomUUID(), email: 'wildXcard@openkey.test', emailVerified: true } });
      const { response } = await googleCallback({ sub: 'underscore-sub', email: 'wild_card@openkey.test', email_verified: true });
      expect(new URL(response.headers.get('location')!).searchParams.get('error')).toBe('new_account');
      expect(await prisma.account.count()).toBe(0);
    });

    test('unknown verified email creates only after bound confirmation, once', async () => {
      const email = 'confirmed-google@openkey.test';
      const { response } = await googleCallback({ sub: 'new-sub', email, email_verified: true });
      const continuation = new URL(response.headers.get('location')!).searchParams.get('continuation');
      expect(continuation).toBeTruthy();
      expect(response.headers.get('referrer-policy')).toBe('no-referrer');
      expect(await prisma.user.count({ where: { email } })).toBe(0);
      const missingBinding = await post('/api/auth/social/confirm', { continuation });
      expect(missingBinding.status).toBe(400);
      const confirmed = await post('/api/auth/social/confirm', { continuation }, cookies(response));
      expect(confirmed.status).toBe(200);
      expect(cookies(confirmed)).toContain('session_token=');
      const user = await prisma.user.findUniqueOrThrow({ where: { email } });
      expect(user.emailVerified).toBe(true);
      expect(await prisma.ethereumKey.count({ where: { userId: user.id, isCanonicalTinyCloud: true } })).toBe(1);
      expect(await prisma.account.count({ where: { userId: user.id, providerId: 'google', accountId: 'new-sub' } })).toBe(1);
      expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(400);
    });

    test('Google confirmation retains the #276 email OTP session flow when Apple is off', async () => {
      const email = 'new-google-otp@openkey.test';
      const { response } = await googleCallback({ sub: 'new-google-otp-sub', email, email_verified: true });
      const continuation = new URL(response.headers.get('location')!).searchParams.get('continuation');
      expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(200);
      const user = await prisma.user.findUniqueOrThrow({ where: { email } });
      expect(user.socialCreatedProvider).toBeNull();
      await prisma.session.deleteMany({ where: { userId: user.id } });
      const otp = await auth.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
      const signedIn = await post('/api/auth/sign-in/email-otp', { email, otp });
      expect(signedIn.status).toBe(200);
      const payload = await signedIn.json() as { token: string; user: { email: string } };
      expect(Object.keys(payload).sort()).toEqual(['token', 'user']);
      expect(payload.user.email).toBe(email);
      expect(cookies(signedIn)).toContain('session_token=');
      expect(await prisma.session.count({ where: { userId: user.id } })).toBe(1);
    });

    test('a provider identity claimed before confirmation leaves no orphan user or key', async () => {
      const email = 'conflicted@openkey.test';
      const { response } = await googleCallback({ sub: 'claimed-sub', email, email_verified: true });
      const continuation = new URL(response.headers.get('location')!).searchParams.get('continuation');
      const owner = await prisma.user.create({ data: { id: randomUUID(), email: 'owner@openkey.test', emailVerified: true } });
      await prisma.account.create({ data: { id: randomUUID(), userId: owner.id, providerId: 'google', accountId: 'claimed-sub' } });
      expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(400);
      expect(await prisma.user.count({ where: { email } })).toBe(0);
      expect(await prisma.ethereumKey.count()).toBe(0);
      expect(await prisma.account.count({ where: { providerId: 'google', accountId: 'claimed-sub' } })).toBe(1);
    });

    test('explicit requestSignUp still requires confirmation and expired continuations cannot create', async () => {
      const email = 'explicit-signup@openkey.test';
      const { response } = await googleCallback({ sub: 'explicit-signup-sub', email, email_verified: true }, '', false, true);
      const continuation = new URL(response.headers.get('location')!).searchParams.get('continuation');
      expect(continuation).toBeTruthy();
      expect(await prisma.user.count()).toBe(0);
      await prisma.verification.updateMany({
        where: { identifier: { startsWith: 'openkey-google-confirm:' } },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      expect((await post('/api/auth/social/confirm', { continuation }, cookies(response))).status).toBe(400);
      expect(await prisma.user.count()).toBe(0);
    });

    test('native confirmation is bound to the original signed authorize query', async () => {
      const callback = `${ORIGIN}/auth/login?tinycloud_request=signed-request&client_id=native-client&native_social_error=1`;
      const start = await post('/api/auth/sign-in/social', {
        provider: 'google', callbackURL: callback, errorCallbackURL: callback, disableRedirect: true,
      });
      const startUrl = new URL((await start.json() as { url: string }).url);
      const code = randomUUID();
      profiles.set(code, { sub: 'native-sub', email: 'native@openkey.test', email_verified: true });
      const response = await call(`/api/auth/callback/google?state=${encodeURIComponent(startUrl.searchParams.get('state')!)}&code=${code}`, {
        headers: { cookie: cookies(start) },
      });
      const target = new URL(response.headers.get('location')!);
      const continuation = target.searchParams.get('continuation');
      expect(target.searchParams.get('error')).toBe('new_account');
      expect(continuation).toBeTruthy();
      const query = new URLSearchParams(target.searchParams);
      query.delete('error');
      query.delete('continuation');
      query.delete('native_social_error');
      const cookie = cookies(response);
      const modified = new URLSearchParams(query);
      modified.set('client_id', 'another-client');
      expect((await post('/api/auth/social/confirm', { continuation, oauthQuery: modified.toString() }, cookie)).status).toBe(400);
      expect(await prisma.user.count()).toBe(0);
      expect((await post('/api/auth/social/confirm', { continuation, oauthQuery: query.toString() }, cookie)).status).toBe(200);
      expect(await prisma.user.count()).toBe(1);
    });

    test('link-social refuses session without email OTP, including after passkey sign-in', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'link@openkey.test', emailVerified: true } });
      const cookie = await signedInCookie(user.email);
      const initial = await post('/api/auth/link-social', { provider: 'google', disableRedirect: true }, cookie);
      expect(initial.status).toBe(403);
      await prisma.passkey.create({ data: {
        id: randomUUID(), userId: user.id, publicKey: 'test-key', credentialID: randomUUID(),
        deviceType: 'singleDevice', backedUp: false,
      } });
      const passkeyCookie = await signedInCookie(user.email);
      await prisma.session.updateMany({ where: { userId: user.id }, data: { lastPasskeyAt: new Date() } });
      const afterPasskeySignIn = await post('/api/auth/link-social', { provider: 'google', disableRedirect: true }, passkeyCookie);
      expect(afterPasskeySignIn.status).toBe(403);
    });

    test('step-up accepts only its own code, stamps the current session and permits explicit link', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'explicit@openkey.test', emailVerified: true } });
      const cookie = await signedInCookie(user.email);
      const signInCode = await auth.api.createVerificationOTP({ body: { email: user.email, type: 'sign-in' } });
      const invalid = await post('/api/account/step-up/email-otp/verify', { code: signInCode }, cookie);
      expect(invalid.status).toBe(400);
      await stepUp(cookie, user.id);
      const sessionCount = await prisma.session.count({ where: { userId: user.id } });
      expect(sessionCount).toBe(1);
      const { response } = await googleCallback({ sub: 'explicit-sub', email: user.email, email_verified: true }, cookie, true);
      expect(response.status).toBe(302);
      expect(await prisma.account.count({ where: { userId: user.id, providerId: 'google', accountId: 'explicit-sub' } })).toBe(1);
      expect(await prisma.session.count({ where: { userId: user.id } })).toBe(sessionCount);
    });

    test('revoking the originating session prevents a pending Google link', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'revoked-link@openkey.test', emailVerified: true } });
      const cookie = await signedInCookie(user.email);
      await stepUp(cookie, user.id);
      const start = await post('/api/auth/link-social', { provider: 'google', disableRedirect: true }, cookie);
      expect(start.status).toBe(200);
      const state = new URL((await start.json() as { url: string }).url).searchParams.get('state');
      expect(state).toBeTruthy();
      await prisma.session.deleteMany({ where: { userId: user.id } });
      const code = randomUUID();
      profiles.set(code, { sub: 'revoked-sub', email: user.email, email_verified: true });
      await call(`/api/auth/callback/google?state=${encodeURIComponent(state!)}&code=${code}`, {
        headers: { cookie: cookies(start) },
      });
      expect(await prisma.account.count({ where: { userId: user.id } })).toBe(0);
    });

    test('an expired step-up prevents a pending Google link', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'expired-link@openkey.test', emailVerified: true } });
      const cookie = await signedInCookie(user.email);
      await stepUp(cookie, user.id);
      const start = await post('/api/auth/link-social', { provider: 'google', disableRedirect: true }, cookie);
      expect(start.status).toBe(200);
      const state = new URL((await start.json() as { url: string }).url).searchParams.get('state');
      expect(state).toBeTruthy();
      await prisma.session.updateMany({ where: { userId: user.id }, data: { lastEmailOtpAt: new Date(Date.now() - 6 * 60 * 1000) } });
      const code = randomUUID();
      profiles.set(code, { sub: 'expired-link-sub', email: user.email, email_verified: true });
      await call(`/api/auth/callback/google?state=${encodeURIComponent(state!)}&code=${code}`, {
        headers: { cookie: cookies(start) },
      });
      expect(await prisma.account.count({ where: { userId: user.id } })).toBe(0);
    });

    test('three incorrect step-up codes exhaust the code without issuing another session', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'attempts@openkey.test', emailVerified: true } });
      const cookie = await signedInCookie(user.email);
      const originalSessions = await prisma.session.count({ where: { userId: user.id } });
      expect((await post('/api/account/step-up/email-otp/send', {}, cookie)).status).toBe(200);
      const row = await prisma.verification.findFirstOrThrow({
        where: { identifier: { startsWith: 'openkey-account-step-up-otp:' } },
      });
      const code = row.value.split(':')[0];
      const wrong = code === '000000' ? '000001' : '000000';
      for (let attempt = 0; attempt < 3; attempt++) {
        expect((await post('/api/account/step-up/email-otp/verify', { code: wrong }, cookie)).status).toBe(400);
      }
      expect((await post('/api/account/step-up/email-otp/verify', { code }, cookie)).status).toBe(400);
      expect((await post('/api/account/step-up/email-otp/send', {}, cookie)).status).toBe(200);
      const exhausted = await prisma.verification.findFirstOrThrow({ where: { id: row.id } });
      expect(exhausted.value).toBe(`${code}:3`);
      expect(await prisma.session.count({ where: { userId: user.id } })).toBe(originalSessions);
      expect((await prisma.session.findFirstOrThrow({ where: { userId: user.id } })).lastEmailOtpAt).toBeNull();
    });

    test('expired step-up is refused even when the session remains valid', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'stale@openkey.test', emailVerified: true } });
      const cookie = await signedInCookie(user.email);
      await stepUp(cookie, user.id);
      await prisma.session.updateMany({ where: { userId: user.id }, data: { lastEmailOtpAt: new Date(Date.now() - 6 * 60 * 1000) } });
      expect((await post('/api/auth/link-social', { provider: 'google', disableRedirect: true }, cookie)).status).toBe(403);
    });

    test('a sole social account can be unlinked when verified email remains', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'deliverable@openkey.test', emailVerified: true } });
      await prisma.account.create({ data: { id: randomUUID(), userId: user.id, providerId: 'google', accountId: 'only-sub' } });
      const cookie = await signedInCookie(user.email);
      await stepUp(cookie, user.id);
      const response = await post('/api/auth/unlink-account', { providerId: 'google' }, cookie);
      expect(response.status).toBe(200);
      expect(await prisma.account.count({ where: { userId: user.id } })).toBe(0);
    });

    test('fresh email step-up can unlink on a valid session older than 24 hours', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'older-session@openkey.test', emailVerified: true } });
      await prisma.account.create({ data: { id: randomUUID(), userId: user.id, providerId: 'google', accountId: 'older-sub' } });
      const cookie = await signedInCookie(user.email);
      await prisma.session.updateMany({
        where: { userId: user.id }, data: { createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000) },
      });
      expect((await post('/api/account/social/unlink', { providerId: 'google', accountId: 'older-sub' }, cookie)).status).toBe(403);
      await stepUp(cookie, user.id);
      expect((await post('/api/auth/unlink-account', { providerId: 'google' }, cookie)).status).toBe(403);
      expect((await post('/api/account/social/unlink', { providerId: 'google', accountId: 'older-sub' }, cookie)).status).toBe(200);
      expect(await prisma.account.count({ where: { userId: user.id } })).toBe(0);
    });

    test('unlink refuses leaving an unverified-email user without a usable method', async () => {
      const user = await prisma.user.create({ data: { id: randomUUID(), email: 'no-recovery@openkey.test', emailVerified: false } });
      await prisma.account.createMany({ data: [
        { id: randomUUID(), userId: user.id, providerId: 'google', accountId: 'primary-sub' },
        { id: randomUUID(), userId: user.id, providerId: 'other', accountId: 'secondary-sub' },
      ] });
      const cookie = await signedInCookie(user.email);
      // Email OTP sign-in itself verifies the email; model a later undeliverable
      // address before evaluating whether unlink leaves a usable method.
      await prisma.user.update({ where: { id: user.id }, data: { emailVerified: false } });
      await stepUp(cookie, user.id);
      const response = await post('/api/auth/unlink-account', { providerId: 'google' }, cookie);
      expect(response.status).toBe(403);
      expect(await prisma.account.count({ where: { userId: user.id } })).toBe(2);
      expect((await post('/api/account/social/unlink', { providerId: 'google', accountId: 'primary-sub' }, cookie)).status).toBe(403);
      expect(await prisma.account.count({ where: { userId: user.id } })).toBe(2);
    });
  });
}
