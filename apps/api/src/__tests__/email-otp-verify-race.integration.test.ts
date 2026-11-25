import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import type * as DatabaseModule from '@openkey/db';
import type * as AuthModule from '../auth';
import { EMAIL_CODE_ALLOWED_ATTEMPTS } from '../services/email-code-atomic-verify';

// One email code must sign in exactly once, and every wrong guess must cost an attempt, however many
// requests arrive at the same moment. Better Auth reads the stored code, deletes it without checking the
// delete count, and only then compares, so without OpenKey's atomic grading N concurrent verifications of
// one code create N sessions, and N parallel wrong guesses are all evaluated while their failed-attempt
// increments overwrite each other.
//
// Proven through the real Hono app on the tracked migration chain. Runs in a fresh process: other API
// tests replace @openkey/db and Better Auth globally.
const backend = process.env.OTP_RACE_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '../../../..');

if (!backend) {
  for (const engine of ['pglite', 'postgres']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(
      `email code verification race (${engine})`,
      async () => {
        const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
          cwd: root,
          env: {
            ...process.env,
            OTP_RACE_TEST_CHILD: engine,
            NODE_ENV: 'test',
            TEE_MODE: 'development',
            BETTER_AUTH_URL: 'https://api.openkey.test',
            BETTER_AUTH_SECRET: 'otp-race-isolated-regression-secret-not-for-production',
            WEBAUTHN_RP_ID: 'openkey.test',
            WEBAUTHN_ORIGIN: 'https://openkey.test',
            CORS_ORIGIN: 'https://openkey.test',
            ADMIN_API_KEY: 'otp-race-admin-key',
            RESEND_API_KEY: '',
            APPLE_SIGN_IN_ENABLED: 'false',
            GOOGLE_CLIENT_ID: '',
            GOOGLE_CLIENT_SECRET: '',
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
  const directory = await mkdtemp(join(tmpdir(), 'openkey-otp-race-'));
  const databaseName = `otp_race_${randomUUID().replaceAll('-', '')}`;
  let admin: Client | undefined;
  let prisma: DatabaseModule.PrismaClient;
  let auth: typeof AuthModule.auth;
  let app: { fetch: (request: Request) => Response | Promise<Response> };

  const API = 'https://api.openkey.test';
  const WEB_ORIGIN = 'https://openkey.test';
  const EMAIL = 'racer@openkey.test';

  function signIn(otp: string) {
    return app.fetch(new Request(`${API}/api/auth/sign-in/email-otp`, {
      method: 'POST',
      headers: { origin: WEB_ORIGIN, 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, otp }),
    }));
  }

  /** A real code for the account, issued the way the send step stores it. */
  function issueCode(): Promise<string> {
    return auth.api.createVerificationOTP({ body: { email: EMAIL, type: 'sign-in' } });
  }

  function wrongCode(code: string): string {
    return code === '000000' ? '111111' : '000000';
  }

  /** The stored code row for the account, with the failed attempts Better Auth records in its value. */
  async function storedCode(): Promise<{ rows: number; attempts: number }> {
    const rows = await prisma.verification.findMany({ where: { identifier: `sign-in-otp-${EMAIL}` } });
    const attempts = rows.map((row) => Number.parseInt(row.value.slice(row.value.lastIndexOf(':') + 1), 10));
    return { rows: rows.length, attempts: attempts.length === 0 ? 0 : Math.max(...attempts) };
  }

  function statuses(responses: Response[]): Record<number, number> {
    const counts: Record<number, number> = {};
    for (const response of responses) counts[response.status] = (counts[response.status] ?? 0) + 1;
    return counts;
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
    // Route singletons capture DATABASE_URL on import, so the app loads only after the disposable
    // database exists.
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    ({ auth } = await import('../auth'));
    app = (await import('../index')).default;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await admin.end();
    }
    await rm(directory, { recursive: true, force: true });
  });

  beforeEach(async () => {
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "user", "verification", "session" CASCADE`);
    await prisma.user.create({ data: { id: randomUUID(), email: EMAIL, name: 'Racer', emailVerified: true } });
  });

  describe('one email code under concurrent verification', () => {
    test.each([3, 10])('%i simultaneous sign-ins with one valid code create one session', async (requests) => {
      const code = await issueCode();

      const responses = await Promise.all(Array.from({ length: requests }, () => signIn(code)));
      const bodies = await Promise.all(responses.map((response) => response.json() as Promise<Record<string, unknown>>));

      expect(statuses(responses)).toEqual({ 200: 1, 400: requests - 1 });
      for (const [index, body] of bodies.entries()) {
        if (responses[index]!.status !== 200) expect(body.code).toBe('INVALID_OTP');
      }
      const tokens = bodies.filter((body) => typeof body.token === 'string').map((body) => body.token);
      expect(new Set(tokens).size).toBe(1);
      expect(await prisma.session.count()).toBe(1);
      expect(await storedCode()).toEqual({ rows: 0, attempts: 0 });
    });

    test('simultaneous wrong codes each cost an attempt', async () => {
      const code = await issueCode();
      const wrong = wrongCode(code);

      const responses = await Promise.all(
        Array.from({ length: EMAIL_CODE_ALLOWED_ATTEMPTS }, () => signIn(wrong)),
      );

      expect(statuses(responses)).toEqual({ 400: EMAIL_CODE_ALLOWED_ATTEMPTS });
      // Every guess is counted: the code has none of its attempts left, so the right one is refused too.
      expect(await storedCode()).toEqual({ rows: 1, attempts: EMAIL_CODE_ALLOWED_ATTEMPTS });
      const after = await signIn(code);
      expect(after.status).toBe(403);
      expect((await after.json() as { code: string }).code).toBe('TOO_MANY_ATTEMPTS');
      expect(await prisma.session.count()).toBe(0);
    });

    test('a burst of wrong codes exhausts the code rather than outrunning the limit', async () => {
      const code = await issueCode();
      const wrong = wrongCode(code);

      const responses = await Promise.all(Array.from({ length: 10 }, () => signIn(wrong)));

      expect(responses.some((response) => response.status === 200)).toBe(false);
      // Spent, so no later request can keep guessing against it.
      expect(await storedCode()).toEqual({ rows: 0, attempts: 0 });
      expect((await signIn(code)).status).not.toBe(200);
      expect(await prisma.session.count()).toBe(0);
    });
  });

  // A resend adds a row instead of replacing one, so the account can hold an older code that is still
  // unexpired. Spending the newest must take the older ones with it, or the next request is graded
  // against a superseded code with a fresh set of attempts.
  describe('a superseded code after a resend', () => {
    test('cannot be revived once the newest code is exhausted', async () => {
      const first = await issueCode();
      const second = await issueCode();
      expect(second).not.toBe(first);
      expect(await storedCode()).toEqual({ rows: 2, attempts: 0 });

      const wrong = wrongCode(second);
      for (let attempt = 0; attempt < EMAIL_CODE_ALLOWED_ATTEMPTS; attempt += 1) {
        expect((await signIn(wrong)).status).toBe(400);
      }
      const exhausting = await signIn(wrong);
      expect(exhausting.status).toBe(403);
      expect((await exhausting.json() as { code: string }).code).toBe('TOO_MANY_ATTEMPTS');

      const revived = await signIn(first);
      expect(revived.status).not.toBe(200);
      expect(await prisma.session.count()).toBe(0);
      expect(await storedCode()).toEqual({ rows: 0, attempts: 0 });
    });

    test('cannot be revived once the newest code signs in', async () => {
      const first = await issueCode();
      const second = await issueCode();

      expect((await signIn(second)).status).toBe(200);
      expect(await prisma.session.count()).toBe(1);

      const revived = await signIn(first);
      expect(revived.status).toBe(400);
      expect((await revived.json() as { code: string }).code).toBe('INVALID_OTP');
      expect(await prisma.session.count()).toBe(1);
      expect(await storedCode()).toEqual({ rows: 0, attempts: 0 });
    });

    test('does not survive simultaneous sign-ins with the newest code', async () => {
      const first = await issueCode();
      const second = await issueCode();

      const responses = await Promise.all(Array.from({ length: 10 }, () => signIn(second)));

      expect(statuses(responses)).toEqual({ 200: 1, 400: 9 });
      expect((await signIn(first)).status).not.toBe(200);
      expect(await prisma.session.count()).toBe(1);
      expect(await storedCode()).toEqual({ rows: 0, attempts: 0 });
    });
  });
}
