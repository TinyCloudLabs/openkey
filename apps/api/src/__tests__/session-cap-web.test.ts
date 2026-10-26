// The 30-day cap on web sessions through the real OpenKey auth (Better Auth with the
// tracked database migrations on PGlite): the refresh-on-use path of /api/auth/get-session.
//
// API unit tests replace modules process-wide, so this runs in a separate process, as
// oauth-mcp-registration.test.ts does.

import './tc1777-test-env';
import { afterAll, afterEach, beforeAll, describe, expect, setSystemTime, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_SESSION_CAP_TEST_CHILD !== '1') {
  test('web sessions are capped at 30 days through the real auth', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_SESSION_CAP_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'session-cap-isolated-test-secret-0123456789abcdef',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: 'https://openkey.test',
        CORS_ORIGIN: 'https://openkey.test',
        RESEND_API_KEY: '',
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
  }, 180_000);
} else {
  const DAY = 86_400_000;
  // A moment fixed for every case, so the new expiry and the cookie's Max-Age are exact.
  const NOW = new Date('2026-10-26T12:00:00.000Z');
  let directory: string;
  let prisma: PrismaClient;
  let authModule: typeof import('../auth');
  let app: { fetch: (request: Request) => Response | Promise<Response> };

  beforeAll(async () => {
    directory = await mkdtemp('/var/tmp/tc2101-session-cap.');
    const database = new PGlite(directory);
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) {
        await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
    } finally {
      await database.close();
    }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    await prisma.user.create({ data: { id: 'u1', email: 'u1@example.test', name: 'U One', emailVerified: true } });
  }, 90_000);

  afterAll(async () => {
    setSystemTime();
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  afterEach(() => setSystemTime());

  /** A session row created `createdDaysAgo` days before NOW that expires `expiresInDays` after it, and its cookie. */
  async function session(id: string, createdDaysAgo: number, expiresInDays: number) {
    const token = randomUUID();
    const createdAt = new Date(NOW.getTime() - createdDaysAgo * DAY);
    await prisma.session.create({ data: { id, userId: 'u1', token, createdAt, updatedAt: createdAt, expiresAt: new Date(NOW.getTime() + expiresInDays * DAY) } });
    const context = await authModule.auth.$context;
    const cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, token, context.secret)).split(';')[0]!;
    return { id, cookie, createdAt };
  }

  async function use(cookie: string) {
    const response = await app.fetch(new Request('https://api.openkey.test/api/auth/get-session', { headers: { cookie } }));
    const text = await response.text();
    const header = response.headers.get('set-cookie') ?? '';
    const maxAge = /Max-Age=(-?\d+)/.exec(header)?.[1];
    return { status: response.status, body: text === 'null' ? null : JSON.parse(text) as { session: { expiresAt: string; createdAt: string } }, maxAge: maxAge === undefined ? undefined : Number(maxAge) };
  }

  const expiry = async (id: string) => (await prisma.session.findUnique({ where: { id } }))?.expiresAt.getTime();

  describe('refresh on use', () => {
    test('a young session renews for 7 days exactly as before, and the cookie keeps its 7-day Max-Age', async () => {
      const { id, cookie } = await session('young', 2, 4);
      setSystemTime(NOW);
      const result = await use(cookie);
      expect(result.status).toBe(200);
      expect(await expiry(id)).toBe(NOW.getTime() + 7 * DAY);
      expect(new Date(result.body!.session.expiresAt).getTime()).toBe(NOW.getTime() + 7 * DAY);
      expect(result.maxAge).toBe(7 * 24 * 60 * 60);
    });

    test('a 29-day-old session is extended only to 30 days after it was created', async () => {
      const { id, cookie, createdAt } = await session('day-29', 29, 3);
      setSystemTime(NOW);
      const result = await use(cookie);
      expect(result.status).toBe(200);
      expect(await expiry(id)).toBe(createdAt.getTime() + 30 * DAY);
      expect(await expiry(id)).toBe(NOW.getTime() + 1 * DAY);
      expect(new Date(result.body!.session.expiresAt).getTime()).toBe(NOW.getTime() + 1 * DAY);
      expect(result.maxAge).toBe(24 * 60 * 60);
    });

    test('a 31-day-old session that has not expired yet is not extended, and ends', async () => {
      const { id, cookie, createdAt } = await session('day-31', 31, 3);
      setSystemTime(NOW);
      const first = await use(cookie);
      expect(first.status).toBe(200);
      expect(await expiry(id)).toBe(createdAt.getTime() + 30 * DAY);
      expect(await expiry(id)!).toBeLessThan(NOW.getTime());
      // The cookie is not given a positive lifetime.
      expect(first.maxAge === undefined || first.maxAge <= 0).toBe(true);
      // The next use finds it expired, as for any expired session.
      setSystemTime(new Date(NOW.getTime() + 1000));
      const second = await use(cookie);
      expect(second.body).toBeNull();
      expect(await prisma.session.count({ where: { id } })).toBe(0);
    });

    test('a 31-day-old session that has already expired is still expired, and is not extended', async () => {
      const { id, cookie } = await session('day-31-expired', 31, -1);
      setSystemTime(NOW);
      const result = await use(cookie);
      expect(result.body).toBeNull();
      expect(await prisma.session.count({ where: { id } })).toBe(0);
    });

    test('a session that is not due for a refresh is left as it is', async () => {
      const { id, cookie } = await session('fresh', 0, 7);
      setSystemTime(NOW);
      const before = await expiry(id);
      const result = await use(cookie);
      expect(result.status).toBe(200);
      expect(await expiry(id)).toBe(before);
    });
  });

  describe('a session used every day', () => {
    test('stays signed in for 30 days after sign-in and not a day longer', async () => {
      const { id, cookie } = await session('daily', 0, 7);
      const alive: number[] = [];
      for (let day = 1; day <= 35; day++) {
        setSystemTime(new Date(NOW.getTime() + day * DAY));
        const result = await use(cookie);
        if (result.body) alive.push(day);
        const stored = await expiry(id);
        if (stored !== undefined) expect(stored).toBeLessThanOrEqual(NOW.getTime() + 30 * DAY);
      }
      expect(alive).toEqual(Array.from({ length: 30 }, (_, index) => index + 1));
      expect(await prisma.session.count({ where: { id } })).toBe(0);
    }, 60_000);
  });

  describe('signing in again', () => {
    test('creates a session with a new creation time, 7 days long, and its own 30 days', async () => {
      const context = await authModule.auth.$context;
      setSystemTime(NOW);
      const first = await context.internalAdapter.createSession('u1');
      expect(first.createdAt.getTime()).toBe(NOW.getTime());
      expect(first.expiresAt.getTime()).toBe(NOW.getTime() + 7 * DAY);

      // Signing in 25 days later is a new session: its own creation time and 7 days.
      setSystemTime(new Date(NOW.getTime() + 25 * DAY));
      const again = await context.internalAdapter.createSession('u1');
      expect(again.token).not.toBe(first.token);
      expect(again.createdAt.getTime()).toBe(NOW.getTime() + 25 * DAY);
      expect(again.expiresAt.getTime()).toBe(NOW.getTime() + 32 * DAY);

      // Used 6 days after that sign-in it renews for 7 days, which is inside its own 30.
      setSystemTime(new Date(NOW.getTime() + 31 * DAY));
      const cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, again.token, context.secret)).split(';')[0]!;
      expect((await use(cookie)).status).toBe(200);
      expect(await expiry(again.id)).toBe(NOW.getTime() + 38 * DAY);
    });
  });
}
