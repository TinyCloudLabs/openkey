import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { generateCodeChallenge } from 'better-auth/oauth2';
import type * as DatabaseModule from '@openkey/db';
import type * as AuthModule from '../apps/api/src/auth';

// TC-1114: a verified email code for an address with no account must not
// create one. The API answers NEW_ACCOUNT_CONFIRMATION_REQUIRED with a
// single-use sign-up token, and only /sign-up/email-otp creates the account.
// Proven through the real Hono app on the tracked migration chain. Runs in a
// fresh process: other API tests replace @openkey/db and Better Auth globally.
const backend = process.env.TC1114_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');

if (!backend) {
  for (const engine of ['pglite', 'postgres']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(
      `TC-1114 email sign-up confirmation (${engine})`,
      async () => {
        const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
          cwd: root,
          env: {
            ...process.env,
            TC1114_TEST_CHILD: engine,
            NODE_ENV: 'test',
            TEE_MODE: 'development',
            BETTER_AUTH_URL: 'https://api.openkey.test',
            BETTER_AUTH_SECRET: 'tc1114-isolated-regression-secret-not-for-production',
            WEBAUTHN_RP_ID: 'openkey.test',
            WEBAUTHN_ORIGIN: 'https://openkey.test',
            CORS_ORIGIN: 'https://openkey.test',
            ADMIN_API_KEY: 'tc1114-admin-key',
            RESEND_API_KEY: '',
            GOOGLE_CLIENT_ID: '',
            GOOGLE_CLIENT_SECRET: '',
            TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA',
          },
          stdout: 'pipe',
          stderr: 'pipe',
        });
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
          child.exited,
        ]);
        expect(exitCode, stdout + stderr).toBe(0);
      },
      300_000,
    );
  }
} else {
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc1114-'));
  const databaseName = `tc1114_${randomUUID().replaceAll('-', '')}`;
  let admin: Client | undefined;
  let prisma: DatabaseModule.PrismaClient;
  let auth: typeof AuthModule.auth;
  let app: { fetch: (request: Request) => Response | Promise<Response> };

  const API = 'https://api.openkey.test';
  const WEB_ORIGIN = 'https://openkey.test';
  const KNOWN = 'returning@openkey.test';

  // Everything the API prints while a test runs; the email must never appear.
  const output: string[] = [];
  const stdoutWrite = process.stdout.write.bind(process.stdout);

  function call(path: string, init: RequestInit = {}) {
    return app.fetch(new Request(`${API}${path}`, init));
  }

  function json(path: string, body: unknown) {
    return call(path, { method: 'POST', headers: { origin: WEB_ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  }

  // Cloudflare's public test secret accepts any token (see apps/api/src/services/turnstile.ts).
  const TURNSTILE_TEST_TOKEN = 'XXXX.DUMMY.TOKEN.XXXX';
  function signUp(body: Record<string, unknown>) {
    return json('/api/auth/sign-up/email-otp', { turnstileToken: TURNSTILE_TEST_TOKEN, ...body });
  }

  // A real code for any address, issued the way the send step stores it.
  async function otpFor(email: string): Promise<string> {
    return auth.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
  }

  function sessionCookie(response: Response): string | undefined {
    return response.headers.getSetCookie().find((value) => value.includes('session_token='));
  }

  async function accountsFor(email: string) {
    const users = await prisma.user.findMany({ where: { email }, select: { id: true } });
    const keys = await prisma.ethereumKey.count({ where: { userId: { in: users.map((user) => user.id) } } });
    return { users: users.length, keys };
  }

  /** Unknown email + valid code: the "new account" answer and its token. */
  async function newAccountToken(email: string): Promise<string> {
    const response = await json('/api/auth/sign-in/email-otp', { email, otp: await otpFor(email) });
    expect(response.status, await response.clone().text()).toBe(403);
    const body = await response.json() as { code: string; signupToken: string };
    expect(body.code).toBe('NEW_ACCOUNT_CONFIRMATION_REQUIRED');
    return body.signupToken;
  }

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    let connectionString: string;
    if (backend === 'postgres') {
      if (!postgresUrl) throw new Error('OPENKEY_TEST_POSTGRES_URL is required for PostgreSQL coverage');
      // Never migrate the supplied database; all data lives in a disposable one.
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
      } finally {
        await migrationConnection.end();
      }
    } else {
      const database = new PGlite(directory);
      try {
        for (const migration of migrations) {
          await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
        }
      } finally {
        await database.close();
      }
      connectionString = `pglite:${directory}`;
    }
    process.env.DATABASE_URL = connectionString;
    // Route singletons capture DATABASE_URL on import, so the app loads only
    // after the disposable database exists.
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    ({ auth } = await import('../apps/api/src/auth'));
    app = (await import('../apps/api/src/index')).default;
  }, 120_000);

  afterAll(async () => {
    process.stdout.write = stdoutWrite;
    await prisma?.$disconnect();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await admin.end();
    }
    await rm(directory, { recursive: true, force: true });
  });

  beforeEach(async () => {
    process.stdout.write = stdoutWrite;
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "user", "verification" CASCADE`);
    await prisma.user.create({ data: { id: randomUUID(), email: KNOWN, name: 'Returning', emailVerified: true } });
    output.length = 0;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      output.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
  });

  describe('TC-1114 email sign-up confirmation', () => {
    test('unknown email + valid code answers "new account" and creates nothing', async () => {
      const email = 'newcomer@openkey.test';
      const response = await json('/api/auth/sign-in/email-otp', { email, otp: await otpFor(email) });
      const body = await response.json() as Record<string, unknown>;

      expect(response.status).toBe(403);
      expect(body.code).toBe('NEW_ACCOUNT_CONFIRMATION_REQUIRED');
      expect(typeof body.signupToken).toBe('string');
      expect(Object.keys(body).sort()).toEqual(['code', 'message', 'signupToken', 'turnstileRequired']);
      expect(JSON.stringify(body)).not.toContain(email);
      expect(sessionCookie(response)).toBeUndefined();
      expect(await accountsFor(email)).toEqual({ users: 0, keys: 0 });
      expect(await prisma.user.count()).toBe(1);
    });

    test('the code is spent by the "new account" answer, as a sign-in would spend it', async () => {
      const email = 'spent@openkey.test';
      const otp = await otpFor(email);
      expect((await json('/api/auth/sign-in/email-otp', { email, otp })).status).toBe(403);
      const again = await json('/api/auth/sign-in/email-otp', { email, otp });
      expect(again.status).toBe(400);
      expect((await again.json() as { code: string }).code).toBe('INVALID_OTP');
    });

    test('a sign-up without a Turnstile token creates nothing and keeps the token', async () => {
      const email = 'challenged@openkey.test';
      const signupToken = await newAccountToken(email);
      const missing = await json('/api/auth/sign-up/email-otp', { email, signupToken });
      expect(missing.status).toBe(400);
      expect((await missing.json() as { code: string }).code).toBe('TURNSTILE_REQUIRED');
      expect(await accountsFor(email)).toEqual({ users: 0, keys: 0 });

      // The same token completes once the check passes.
      expect((await signUp({ email, signupToken })).status).toBe(200);
    });

    test('confirming creates the account and its canonical key, and signs in', async () => {
      const email = 'Confirmed@OpenKey.test';
      const signupToken = await newAccountToken(email);
      const response = await signUp({ email, signupToken });
      const body = await response.json() as { token: string; user: { email: string; emailVerified: boolean } };

      expect(response.status).toBe(200);
      expect(body.user).toMatchObject({ email: 'confirmed@openkey.test', emailVerified: true });
      expect(typeof body.token).toBe('string');
      expect(response.headers.get('set-auth-token')?.split('.')[0]).toBe(body.token);
      const cookie = sessionCookie(response)!.split(';')[0]!;
      const session = await (await call('/api/auth/get-session', { headers: { cookie } })).json() as { user: { email: string } };
      expect(session.user.email).toBe('confirmed@openkey.test');

      const user = await prisma.user.findUniqueOrThrow({ where: { email: 'confirmed@openkey.test' } });
      const keys = await prisma.ethereumKey.findMany({ where: { userId: user.id } });
      expect(keys).toHaveLength(1);
      expect(keys[0]).toMatchObject({ isCanonicalTinyCloud: true, keyIndex: 0 });
      expect(await prisma.verification.count({ where: { identifier: { startsWith: 'openkey-email-signup:' } } })).toBe(0);
    });

    test('cancelling or choosing a passkey leaves nothing behind', async () => {
      const email = 'walked-away@openkey.test';
      await newAccountToken(email);
      // Cancel and passkey sign-in never call the sign-up endpoint.
      expect(await accountsFor(email)).toEqual({ users: 0, keys: 0 });
    });

    test('a known email signs in exactly as before', async () => {
      const response = await json('/api/auth/sign-in/email-otp', { email: KNOWN, otp: await otpFor(KNOWN) });
      const body = await response.json() as { token: string; user: { email: string } };

      expect(response.status).toBe(200);
      expect(Object.keys(body).sort()).toEqual(['token', 'user']);
      expect(body.user.email).toBe(KNOWN);
      expect(sessionCookie(response)).toBeDefined();
      expect(await prisma.user.count()).toBe(1);
      expect(await prisma.verification.count({ where: { identifier: { startsWith: 'openkey-email-signup:' } } })).toBe(0);
    });

    test('a wrong code is refused identically for known and unknown emails', async () => {
      await otpFor(KNOWN);
      await otpFor('stranger@openkey.test');
      const known = await json('/api/auth/sign-in/email-otp', { email: KNOWN, otp: '000001' });
      const unknown = await json('/api/auth/sign-in/email-otp', { email: 'stranger@openkey.test', otp: '000001' });
      expect(known.status).toBe(unknown.status);
      expect(await known.json()).toEqual(await unknown.json());
      expect(await accountsFor('stranger@openkey.test')).toEqual({ users: 0, keys: 0 });
    });

    test('sign-up without a verified code is refused', async () => {
      for (const body of [
        { email: 'forged@openkey.test' },
        { email: 'forged@openkey.test', signupToken: '' },
        { email: 'forged@openkey.test', signupToken: 'not-a-token' },
        { email: 'forged@openkey.test', signupToken: 42 },
        { signupToken: 'not-a-token' },
      ]) {
        const response = await json('/api/auth/sign-up/email-otp', body);
        expect(response.status).toBe(400);
        expect((await response.json() as { code: string }).code).toBe('INVALID_SIGNUP_TOKEN');
        expect(sessionCookie(response)).toBeUndefined();
      }
      expect(await accountsFor('forged@openkey.test')).toEqual({ users: 0, keys: 0 });
    });

    test('an expired sign-up token is refused', async () => {
      const email = 'late@openkey.test';
      const signupToken = await newAccountToken(email);
      await prisma.verification.updateMany({
        where: { identifier: { startsWith: 'openkey-email-signup:' } },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      const response = await signUp({ email, signupToken });
      expect(response.status).toBe(400);
      expect((await response.json() as { code: string }).code).toBe('INVALID_SIGNUP_TOKEN');
      expect(await accountsFor(email)).toEqual({ users: 0, keys: 0 });
    });

    test('a sign-up token is single-use, including under concurrent replay', async () => {
      const email = 'replayed@openkey.test';
      const signupToken = await newAccountToken(email);
      const raced = await Promise.all([1, 2, 3].map(() => signUp({ email, signupToken })));
      expect(raced.map((response) => response.status).sort()).toEqual([200, 400, 400]);

      const replay = await signUp({ email, signupToken });
      expect(replay.status).toBe(400);
      expect((await replay.json() as { code: string }).code).toBe('INVALID_SIGNUP_TOKEN');
      expect(await accountsFor(email)).toEqual({ users: 1, keys: 1 });
    });

    test('a sign-up token only creates the email whose code was verified', async () => {
      const email = 'verified@openkey.test';
      const signupToken = await newAccountToken(email);
      for (const other of ['victim@openkey.test', KNOWN, 'verified@openkey.test.evil']) {
        const response = await signUp({ email: other, signupToken });
        expect(response.status).toBe(400);
        expect((await response.json() as { code: string }).code).toBe('INVALID_SIGNUP_TOKEN');
      }
      expect(await accountsFor('victim@openkey.test')).toEqual({ users: 0, keys: 0 });
      // The rightful confirmation still works.
      expect((await signUp({ email, signupToken })).status).toBe(200);
    });

    test('two verified codes for one email confirmed at once create one account', async () => {
      const email = 'two-tabs@openkey.test';
      const first = await newAccountToken(email);
      const second = await newAccountToken(email);
      const responses = await Promise.all([first, second].map((signupToken) => signUp({ email, signupToken })));
      expect(responses.map((response) => response.status).sort()).toEqual([200, 400]);
      const loser = responses.find((response) => response.status === 400)!;
      expect((await loser.json() as { code: string }).code).toBe('ACCOUNT_ALREADY_EXISTS');
      expect(await accountsFor(email)).toEqual({ users: 1, keys: 1 });
    });

    test('a token for an email that gained an account meanwhile creates nothing', async () => {
      const email = 'raced-social@openkey.test';
      const signupToken = await newAccountToken(email);
      await prisma.user.create({ data: { id: randomUUID(), email, name: '', emailVerified: true } });
      const response = await signUp({ email, signupToken });
      expect(response.status).toBe(400);
      expect((await response.json() as { code: string }).code).toBe('ACCOUNT_ALREADY_EXISTS');
      expect(sessionCookie(response)).toBeUndefined();
      expect(await prisma.user.count({ where: { email } })).toBe(1);
    });

    test('requesting a code looks the same for known and unknown emails', async () => {
      const request = (email: string) => json('/api/auth/email-otp/send-verification-otp', { email, type: 'sign-in' });
      const shape = async (response: Response) => ({
        status: response.status,
        body: await response.json(),
        headers: [...response.headers.keys()].filter((name) => name !== 'x-request-id').sort(),
      });
      expect(await shape(await request(KNOWN))).toEqual(await shape(await request('nobody@openkey.test')));
      // Both take the same delivery path (no mailer is configured here).
      const deliveries = output.filter((line) => line.includes('"otp_delivery_unconfigured"')).length;
      expect(deliveries).toBe(2);

      // Timing: interleaved samples; the two medians stay within noise.
      const samples: Record<'known' | 'unknown', number[]> = { known: [], unknown: [] };
      for (let index = 0; index < 15; index += 1) {
        for (const [kind, email] of [['known', KNOWN], ['unknown', `nobody-${index}@openkey.test`]] as const) {
          const started = performance.now();
          expect((await request(email)).status).toBe(200);
          samples[kind].push(performance.now() - started);
        }
      }
      const median = (values: number[]) => values.sort((a, b) => a - b)[Math.floor(values.length / 2)]!;
      const [known, unknown] = [median(samples.known), median(samples.unknown)];
      expect(Math.abs(known - unknown)).toBeLessThan(Math.max(25, 0.5 * Math.max(known, unknown)));
      expect(await prisma.user.count()).toBe(1);
    });

    test('logs carry allowlisted events only and never the email', async () => {
      const email = 'private.person@openkey.test';
      const signupToken = await newAccountToken(email);
      await signUp({ email: 'someone.else@openkey.test', signupToken });
      await signUp({ email, signupToken });
      const lines = output.flatMap((chunk) => chunk.split('\n')).filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
      const events = lines.map((line) => line.event);
      expect(events).toContain('auth_email_signup_confirmation_required');
      expect(events).toContain('auth_email_signup_confirmed');
      expect(lines.find((line) => line.event === 'auth_email_signup_refused')).toMatchObject({ error_code: 'signup_token_invalid' });
      const printed = output.join('\n');
      for (const secret of [email, 'someone.else@openkey.test', signupToken]) expect(printed).not.toContain(secret);
    });

    test('an OAuth sign-up continues the authorize request after confirmation', async () => {
      const redirectUri = 'https://app.openkey.test/callback';
      const created = await call('/api/admin/oauth/clients', {
        method: 'POST',
        headers: { authorization: 'Bearer tc1114-admin-key', 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'TC-1114 app', type: 'spa', redirectUris: [redirectUri] }),
      });
      expect(created.status, await created.clone().text()).toBe(201);
      const clientId = (await created.json() as { client: { clientId: string } }).client.clientId;
      const authorize = await call(`/api/auth/oauth2/authorize?${new URLSearchParams({
        client_id: clientId,
        response_type: 'code',
        redirect_uri: redirectUri,
        scope: 'openid email',
        state: 'tc1114-state',
        code_challenge: await generateCodeChallenge('tc1114-verifier-tc1114-verifier-tc1114-verifier'),
        code_challenge_method: 'S256',
      })}`);
      expect(authorize.status, await authorize.clone().text()).toBe(302);
      const oauthQuery = new URL(authorize.headers.get('location')!).searchParams.toString();

      const email = 'oauth-newcomer@openkey.test';
      const signIn = await json('/api/auth/sign-in/email-otp', { email, otp: await otpFor(email), oauth_query: oauthQuery });
      expect(signIn.status).toBe(403);
      const { signupToken } = await signIn.json() as { signupToken: string };
      expect(await accountsFor(email)).toEqual({ users: 0, keys: 0 });

      const confirmed = await signUp({ email, signupToken, oauth_query: oauthQuery });
      expect(confirmed.status, await confirmed.clone().text()).toBe(200);
      const body = await confirmed.json() as { redirect?: boolean; url?: string };
      expect(body.redirect).toBe(true);
      const next = new URL(body.url!);
      expect(next.pathname === '/oauth/consent' || next.href.startsWith(redirectUri)).toBe(true);
      expect(await accountsFor(email)).toEqual({ users: 1, keys: 1 });
    });
  });
}
