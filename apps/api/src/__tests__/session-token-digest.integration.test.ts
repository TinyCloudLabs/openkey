import { expect, setSystemTime, test } from 'bun:test';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';

// Session tokens are stored as a digest. A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
const MIGRATION = '20261124_0003_session_token_digest';
const digestOf = (token: string) => createHash('sha256').update(`openkey-session-token\0${token}`).digest('hex');

if (!process.env.TC_SESSION_DIGEST_CHILD) {
  test('session tokens are stored as digests, in a fresh process', async () => {
    const directory = await mkdtemp('/var/tmp/openkey-session-digest-');
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC_SESSION_DIGEST_CHILD: directory, HOME: directory, TMPDIR: directory,
          BUN_INSTALL_CACHE_DIR: join(directory, 'bun-cache'), NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: 'http://localhost:3326', BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
          WEBAUTHN_ORIGIN: 'https://openkey.example', WEBAUTHN_RP_ID: 'localhost',
          CORS_ORIGIN: 'https://openkey.example,https://console.openkey.example', CONSOLE_ORIGIN: 'https://console.openkey.example',
          TINYCLOUD_BOOTSTRAP_ON_SIGN: 'off',
          RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
          DATABASE_URL: `pglite:${join(directory, 'db')}` },
        stdout: 'pipe', stderr: 'pipe',
      });
      const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(code, stdout + stderr).toBe(0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }, 240_000);
} else {
  const directory = process.env.TC_SESSION_DIGEST_CHILD!;
  const root = resolve(import.meta.dir, '../../../..');
  const migrationsDirectory = join(root, 'packages/db/prisma/migrations');
  const OPENKEY = 'https://openkey.example';
  const api = process.env.BETTER_AUTH_URL!;
  const migrationNames = async () =>
    (await readdir(migrationsDirectory, { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();

  // Every migration but the one under test goes in before the app starts; the migration test applies the last one itself.
  const setup = (async () => {
    const database = new PGlite(join(directory, 'db'));
    for (const migration of await migrationNames()) {
      await database.exec(await readFile(join(migrationsDirectory, migration, 'migration.sql'), 'utf8'));
    }
    await database.close();
    const { createPrismaClient } = await import('@openkey/db');
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const { auth } = await import('../auth');
    const app = (await import('../index')).default;
    const prisma = createPrismaClient();
    const authContext = await auth.$context;
    const request = (url: string, init?: RequestInit) => app.fetch(new Request(url, init));
    const json = { origin: OPENKEY, 'content-type': 'application/json' };

    // test@openkey.dev signs in with 000000 in development (auth.ts generateOTP).
    async function signIn(email: string) {
      await request(`${api}/api/auth/email-otp/send-verification-otp`, { method: 'POST', headers: json, body: JSON.stringify({ email, type: 'sign-in' }) });
      const response = await request(`${api}/api/auth/sign-in/email-otp`, { method: 'POST', headers: json, body: JSON.stringify({ email, otp: '000000' }) });
      expect(response.status, await response.clone().text()).toBe(200);
      const issued = response.headers.get('set-auth-token')!;
      expect(issued).toContain('.');
      return { issued, token: decodeURIComponent(issued).split('.')[0]!, response };
    }
    const cookieFor = async (value: string) =>
      (await serializeSignedCookie(authContext.authCookies.sessionToken.name, value, authContext.secret)).split(';')[0]!;
    const storedFor = async (userId: string) =>
      (await prisma.$queryRaw<{ id: string; token: string }[]>`SELECT id, token FROM session WHERE "userId" = ${userId} ORDER BY "createdAt"`);
    // Only this address signs in with 000000. Each test starts from no sessions for it.
    const userId = randomUUID();
    await prisma.user.create({ data: { id: userId, email: 'test@openkey.dev', emailVerified: true } });
    const fresh = async () => {
      await prisma.session.deleteMany({ where: { userId } });
      return userId;
    };
    return { prisma, userId, fresh, authContext, app, request, signIn, cookieFor, storedFor, createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal, createPrismaClient };
  })();

  // Prisma operations are lazy thenables; `rejects` needs a real promise.
  const refused = (operation: PromiseLike<unknown>) => expect(Promise.resolve(operation)).rejects.toThrow('Unsupported session token');

  test('the stored token is the digest of the token the sign-in hands out', async () => {
    const { fresh, signIn, storedFor } = await setup;
    const userId = await fresh();
    const { token, issued } = await signIn('test@openkey.dev');
    const [row] = await storedFor(userId);
    expect(row!.token).not.toBe(token);
    expect(row!.token).toBe(digestOf(token));
    expect(row!.token).toMatch(/^[0-9a-f]{64}$/);
    // The same value Better Auth read back for the cookie: the token, not the digest.
    expect(decodeURIComponent(issued).startsWith(`${token}.`)).toBe(true);
  }, 60_000);

  test('a database row pasted into a request is refused; the issued token still works', async () => {
    const { fresh, authContext, request, signIn, cookieFor, storedFor } = await setup;
    const userId = await fresh();
    const { issued } = await signIn('test@openkey.dev');
    const stored = (await storedFor(userId))[0]!.token;
    const signature = createHmac('sha256', authContext.secret).update(stored).digest('base64');
    const forgedBearer = encodeURIComponent(`${stored}.${signature}`);
    const sessionOf = async (headers: Record<string, string>) => {
      const response = await request(`${api}/api/auth/get-session?disableRefresh=true`, { headers: { origin: OPENKEY, ...headers } });
      return ((await response.json()) as { user?: { id: string } } | null)?.user?.id ?? null;
    };
    const keys = async (headers: Record<string, string>) => (await request(`${api}/api/keys`, { headers: { origin: OPENKEY, ...headers } })).status;

    const attempts: Record<string, string>[] = [
      { authorization: `Bearer ${stored}` },
      { authorization: `Bearer ${forgedBearer}` },
      { cookie: await cookieFor(stored) },
    ];
    for (const headers of attempts) {
      expect(await sessionOf(headers)).toBeNull();
      expect(await keys(headers)).toBe(401);
    }
    expect(await sessionOf({ authorization: `Bearer ${issued}` })).toBe(userId);
    expect(await keys({ authorization: `Bearer ${issued}` })).toBe(200);

    // /session-token signs the token, never the digest.
    const cookie = await cookieFor(decodeURIComponent(issued).split('.')[0]!);
    const fromCookie = await request(`${api}/api/auth/session-token`, { headers: { origin: OPENKEY, cookie } });
    expect(fromCookie.status).toBe(200);
    expect(((await fromCookie.json()) as { token: string }).token).toBe(issued);
  }, 60_000);

  test('refresh keeps the token, sign-out removes the row, other-session revoke keeps the current one, and the listing has no token', async () => {
    const { fresh, request, signIn, cookieFor, storedFor } = await setup;
    const userId = await fresh();
    const first = await signIn('test@openkey.dev');
    const second = await signIn('test@openkey.dev');
    expect((await storedFor(userId)).length).toBe(2);

    // A use past updateAge refreshes the session; the refreshed cookie still carries the token.
    const cookie = await cookieFor(first.token);
    try {
      setSystemTime(new Date(Date.now() + 2 * 86_400_000));
      const refreshed = await request(`${api}/api/auth/get-session`, { headers: { origin: OPENKEY, cookie } });
      expect(refreshed.status).toBe(200);
      const setCookie = decodeURIComponent(refreshed.headers.get('set-cookie') ?? '');
      expect(setCookie).toContain(`=${first.token}.`);
      expect(setCookie).not.toContain(digestOf(first.token));
      const again = await request(`${api}/api/auth/get-session?disableRefresh=true`, { headers: { origin: OPENKEY, cookie } });
      expect(((await again.json()) as { user?: { id: string } } | null)?.user?.id).toBe(userId);

      const listed = await request(`${api}/api/auth/list-sessions`, { headers: { origin: OPENKEY, cookie } });
      expect(listed.status).toBe(200);
      const items = (await listed.json()) as Record<string, unknown>[];
      expect(items.length).toBe(2);
      for (const item of items) expect('token' in item).toBe(false);

      // OpenKey's /revoke-other-sessions ends every session but this one.
      const revoked = await request(`${api}/api/auth/revoke-other-sessions`, { method: 'POST', headers: { origin: OPENKEY, cookie } });
      expect(revoked.status).toBe(200);
      const left = await storedFor(userId);
      expect(left.map((row) => row.token)).toEqual([digestOf(first.token)]);
      expect(left.map((row) => row.token)).not.toContain(digestOf(second.token));
    } finally {
      setSystemTime();
    }

    const out = await request(`${api}/api/auth/sign-out`, { method: 'POST', headers: { origin: OPENKEY, authorization: `Bearer ${first.issued}` } });
    expect(out.status).toBe(200);
    expect((await storedFor(userId)).length).toBe(0);
  }, 90_000);

  test('the embedded sign flow signs with the bearer a real sign-in hands out', async () => {
    const { prisma, fresh, request, signIn, storedFor, createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await setup;
    const userId = await fresh();
    const privateKey = generatePrivateKey();
    const address = getAddressFromPrivateKey(privateKey);
    const sealingContext = randomBytes(32).toString('base64url');
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    const key = await prisma.ethereumKey.create({ data: { userId, address, publicKey: '0x1', sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
    const { issued, token } = await signIn('test@openkey.dev');
    expect((await storedFor(userId))[0]!.token).toBe(digestOf(token));
    const message = [
      'embedding-app.example wants you to sign in with your Ethereum account:', address, '', 'Sign in', '',
      'URI: https://embedding-app.example', 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef12345678', 'Issued At: 2026-11-09T00:00:00.000Z',
    ].join('\n');
    const signed = await request(`${api}/api/keys/${key.id}/sign`, {
      method: 'POST', headers: { ...json(), authorization: `Bearer ${issued}` },
      body: JSON.stringify({ message, requestOrigin: 'https://embedding-app.example' }),
    });
    expect(signed.status, await signed.clone().text()).toBe(200);
    expect(await signed.json()).toMatchObject({ address, format: 'personal_sign' });
  }, 60_000);
  const json = () => ({ origin: OPENKEY, 'content-type': 'application/json' });

  test('the migration ends every session and keeps OAuth refresh tokens', async () => {
    const names = (await migrationNames()).filter((name) => name !== MIGRATION);
    const database = new PGlite(join(directory, 'migration'));
    try {
      for (const name of names) await database.exec(await readFile(join(migrationsDirectory, name, 'migration.sql'), 'utf8'));
      await database.exec(`INSERT INTO "user" (id, email, "emailVerified", name, "createdAt", "updatedAt") VALUES ('u1', 'u1@example.test', true, 'U', now(), now())`);
      await database.exec(`INSERT INTO session (id, "userId", token, "expiresAt", "createdAt", "updatedAt") VALUES
        ('s1', 'u1', 'plain-token-one', now() + interval '1 day', now(), now()),
        ('s2', 'u1', 'plain-token-two', now() + interval '1 day', now(), now())`);
      await database.exec(`INSERT INTO oauth_refresh_token (id, token, "clientId", "userId", "sessionId", "expiresAt") VALUES ('r1', 'hashed-refresh', 'client', 'u1', 's1', now() + interval '1 day')`);
      await database.exec(await readFile(join(migrationsDirectory, MIGRATION, 'migration.sql'), 'utf8'));
      const sessions = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM session');
      const refresh = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM oauth_refresh_token');
      const users = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM "user"');
      expect(sessions.rows[0]!.count).toBe(0);
      expect(refresh.rows[0]!.count).toBe(1);
      expect(users.rows[0]!.count).toBe(1);
    } finally {
      await database.close();
    }
  }, 120_000);

  test('a filter the digest cannot cover fails closed instead of matching or deleting every row', async () => {
    const { prisma, fresh, signIn, storedFor } = await setup;
    const userId = await fresh();
    const { token } = await signIn('test@openkey.dev');
    const before = (await prisma.session.count());
    // Prisma reads `equals: undefined` as no filter at all, which would delete every row.
    await refused(prisma.session.deleteMany({ where: { token: { equals: undefined } } }));
    await refused(prisma.session.deleteMany({ where: { token: undefined as unknown as string } }));
    await refused(prisma.session.deleteMany({ where: { token: '' } }));
    await refused(prisma.session.findFirst({ where: { token: { contains: 'a' } } }));
    await refused(prisma.session.findFirst({ where: { AND: [{ token: { startsWith: 'a' } }] } }));
    expect(await prisma.session.count()).toBe(before);
    expect((await storedFor(userId)).length).toBe(1);
    // A thrown error names the operator and never a token or digest.
    const error = await prisma.session.findFirst({ where: { token: { contains: token } } }).catch((caught: Error) => caught);
    expect(String((error as Error).message)).not.toContain(token);
    expect(String((error as Error).message)).not.toContain(digestOf(token));
  }, 60_000);

  test('every unique and list form of a token filter, and an interactive transaction, hash the token', async () => {
    const { prisma, fresh, storedFor } = await setup;
    const userId = await fresh();
    const [a, b, c] = [randomBytes(24).toString('base64url'), randomBytes(24).toString('base64url'), randomBytes(24).toString('base64url')];
    const base = { userId, expiresAt: new Date(Date.now() + 3_600_000) };
    const created = await prisma.session.create({ data: { id: randomUUID(), token: a, ...base } });
    expect(created.token).toBe(a);
    await prisma.session.createMany({ data: [{ id: randomUUID(), token: b, ...base }] });
    expect((await storedFor(userId)).map((row) => row.token).sort()).toEqual([digestOf(a), digestOf(b)].sort());

    // findUnique and findUniqueOrThrow take the unique input.
    expect((await prisma.session.findUnique({ where: { token: a } }))?.token).toBe(a);
    expect((await prisma.session.findUniqueOrThrow({ where: { token: b } })).id).toBeString();
    expect(await prisma.session.findUnique({ where: { token: digestOf(a) } })).toBeNull();
    // upsert: the unique where and both branches.
    const upsertedNew = await prisma.session.upsert({ where: { token: c }, create: { id: randomUUID(), token: c, ...base }, update: {} });
    expect(upsertedNew.token).toBe(c);
    const upsertedOld = await prisma.session.upsert({ where: { token: c }, create: { id: randomUUID(), token: 'never', ...base }, update: { ipAddress: 'x' } });
    expect(upsertedOld.token).toBe(c);
    expect((await storedFor(userId)).map((row) => row.token)).not.toContain(digestOf('never'));
    // update with a token in the data.
    const rotated = randomBytes(24).toString('base64url');
    await prisma.session.update({ where: { token: c }, data: { token: rotated } });
    expect((await storedFor(userId)).map((row) => row.token)).toContain(digestOf(rotated));
    // list and negation operators.
    expect((await prisma.session.findMany({ where: { token: { in: [a, b] } } })).map((row) => row.token).sort()).toEqual([a, b].sort());
    const others = await prisma.session.findMany({ where: { userId, token: { notIn: [a, b] } } });
    expect(others.length).toBe(1);
    expect('token' in others[0]!).toBe(false);
    expect((await prisma.session.findMany({ where: { userId, NOT: { token: a } } })).length).toBe(2);
    expect(await prisma.session.count({ where: { userId, token: { not: a } } })).toBe(2);
    expect(await prisma.session.count({ where: { OR: [{ token: a }, { token: b }] } })).toBe(2);
    // A row read without a known token has none to give.
    for (const row of await prisma.session.findMany({ where: { userId } })) expect('token' in row).toBe(false);

    // An interactive transaction goes through the same extension.
    await prisma.$transaction(async (tx) => {
      const inTx = randomBytes(24).toString('base64url');
      expect((await tx.session.create({ data: { id: randomUUID(), token: inTx, ...base } })).token).toBe(inTx);
      expect((await tx.session.findFirst({ where: { token: inTx } }))?.token).toBe(inTx);
      const [raw] = await tx.$queryRaw<{ token: string }[]>`SELECT token FROM session WHERE token = ${digestOf(inTx)}`;
      expect(raw!.token).toBe(digestOf(inTx));
      expect(await tx.session.deleteMany({ where: { token: inTx } })).toEqual({ count: 1 });
    });
    // A rolled-back write leaves no row, and deletes by token remove exactly one.
    expect(await prisma.session.deleteMany({ where: { token: a } })).toEqual({ count: 1 });
    expect((await storedFor(userId)).length).toBe(2);
  }, 60_000);

  test('a nested session write or token filter through the user relation is refused', async () => {
    const { prisma, fresh, storedFor } = await setup;
    const userId = await fresh();
    const session = { id: randomUUID(), token: 'nested-token', expiresAt: new Date(Date.now() + 3_600_000) };
    await refused(prisma.user.update({ where: { id: userId }, data: { sessions: { create: session } } }));
    await refused(prisma.user.create({ data: { id: randomUUID(), email: 'nested2@example.test', emailVerified: true, sessions: { create: [session] } } }));
    await refused(prisma.user.upsert({ where: { id: userId }, create: { id: userId, email: 'x@example.test', emailVerified: true }, update: { sessions: { createMany: { data: [session] } } } }));
    await refused(prisma.user.findFirst({ where: { sessions: { some: { token: 'nested-token' } } } }));
    expect((await storedFor(userId)).length).toBe(0);
    expect(await prisma.user.count({ where: { email: 'nested2@example.test' } })).toBe(0);

    // Session rows read through the relation carry no token.
    await prisma.session.create({ data: { ...session, userId } });
    const withSessions = await prisma.user.findUniqueOrThrow({ where: { id: userId }, include: { sessions: true } });
    expect(withSessions.sessions.length).toBe(1);
    expect('token' in withSessions.sessions[0]!).toBe(false);
  }, 60_000);
}
