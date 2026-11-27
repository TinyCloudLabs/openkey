// The account-deletion event feed through the whole API: the deletion route writes one event in its own transaction,
// a refused or rolled-back deletion writes none, the feed returns the events, the retention sweep removes old rows,
// and two deletions cannot commit out of id order. Runs on PGlite, and also on Postgres when OPENKEY_TEST_POSTGRES_URL
// is set, where the two-connection ordering case runs too (PGlite has a single connection).
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
const ORIGIN = 'https://openkey.test';
const API = 'https://api.openkey.test';
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const backend = process.env.OPENKEY_ACCOUNT_DELETION_EVENTS_BACKEND === 'postgres' ? 'postgres' : 'pglite';
// Built at runtime: a fixed credential-shaped literal does not belong in a fixture.
const FEED_BEARER = 'tb' + 'ab'.repeat(16); // 34 characters: the feed needs at least 32

if (process.env.OPENKEY_ACCOUNT_DELETION_EVENTS_CHILD !== '1') {
  for (const engine of ['pglite', 'postgres'] as const) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(`account-deletion events: deletion writes one event, refusals write none, feed, retention, commit order (${engine})`, async () => {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: {
          ...process.env,
          OPENKEY_ACCOUNT_DELETION_EVENTS_CHILD: '1',
          OPENKEY_ACCOUNT_DELETION_EVENTS_BACKEND: engine,
          NODE_ENV: 'test',
          TEE_MODE: 'development',
          BETTER_AUTH_URL: API,
          BETTER_AUTH_SECRET: 'account-deletion-events-ci-isolated-test-secret',
          WEBAUTHN_RP_ID: 'openkey.test',
          WEBAUTHN_ORIGIN: ORIGIN,
          CORS_ORIGIN: ORIGIN,
          OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN: FEED_BEARER,
          RESEND_API_KEY: '',
          GOOGLE_CLIENT_ID: '',
          GOOGLE_CLIENT_SECRET: '',
        },
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(exitCode, stdout + stderr).toBe(0);
    }, 300_000);
  }
} else {
  let directory: string | undefined;
  let admin: Client | undefined;
  const databaseName = `deletion_events_${randomBytes(6).toString('hex')}`;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookieName: string;
  let secret: string;
  let recordAccountDeletionEvent: typeof import('../services/account-deletion-event').recordAccountDeletionEvent;

  const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  if (backend === 'postgres') {
    admin = new Client({ connectionString: postgresUrl });
    await admin.connect();
    await admin.query(`CREATE DATABASE "${databaseName}"`);
    const target = new URL(postgresUrl!);
    target.pathname = `/${databaseName}`;
    const migrationConnection = new Client({ connectionString: target.toString() });
    await migrationConnection.connect();
    try {
      for (const migration of migrations) await migrationConnection.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    } finally { await migrationConnection.end(); }
    process.env.DATABASE_URL = target.toString();
  } else {
    directory = await mkdtemp(join(tmpdir(), 'openkey-deletion-events-'));
    const database = new PGlite(directory);
    try {
      for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    } finally { await database.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
  }
  delete process.env.OPENKEY_DATABASE_SCHEMA;

  beforeAll(async () => {
    // Loaded after DATABASE_URL is set: the API modules open their database when loaded.
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    ({ recordAccountDeletionEvent } = await import('../services/account-deletion-event'));
    const context = await authModule.auth.$context;
    cookieName = context.authCookies.sessionToken.name;
    secret = context.secret;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`).catch(() => undefined);
      await admin.end();
    }
  });

  const newAddress = (checksummed = false) => {
    const hex = randomBytes(20).toString('hex');
    // Mixed case on purpose: addresses go out exactly as stored.
    return checksummed ? `0x${hex.slice(0, 20).toUpperCase()}${hex.slice(20)}` : `0x${hex}`;
  };

  type KeySpec = { keyType?: 'MANAGED' | 'EXTERNAL'; archived?: boolean };
  async function account(keys: KeySpec[] = [{}]) {
    const userId = `deletion-event-${randomUUID()}`;
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: `Name ${userId}`, emailVerified: true } });
    const addresses: string[] = [];
    for (const [keyIndex, spec] of keys.entries()) {
      const address = newAddress(keyIndex % 2 === 0);
      addresses.push(address);
      await prisma.ethereumKey.create({ data: {
        userId, address, publicKey: address, keyIndex, keyType: spec.keyType ?? 'MANAGED', archivedAt: spec.archived ? new Date() : null,
      } });
    }
    const session = async () => {
      const token = randomUUID();
      const id = randomUUID();
      await prisma.session.create({ data: { id, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
      return { id, token, cookie: (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]! };
    };
    return { userId, addresses, session };
  }

  const call = (cookie: string, path: string, method: 'GET' | 'POST', body?: unknown) => app.fetch(new Request(`${API}${path}`, {
    method, headers: { cookie, origin: ORIGIN, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
  const deleteAccount = (cookie: string, confirmation = 'DELETE MY ACCOUNT') => call(cookie, '/api/account/delete', 'POST', { confirmation });
  const feed = (after?: bigint | string, limit?: number) => {
    const query = new URLSearchParams();
    if (after !== undefined) query.set('after', String(after));
    if (limit !== undefined) query.set('limit', String(limit));
    return app.fetch(new Request(`${API}/api/internal/account-deletions?${query}`, { headers: { authorization: `Bearer ${FEED_BEARER}` } }));
  };
  type Feed = { environment: string; events: Array<{ id: string; addresses: string[]; deletedAt: string }>; next: string };
  const readFeed = async (after?: bigint | string, limit?: number) => {
    const response = await feed(after, limit);
    expect(response.status).toBe(200);
    return await response.json() as Feed;
  };
  const eventsHolding = async (address: string) => (await prisma.accountDeletionEvent.findMany()).filter((row) => row.addresses.includes(address));
  const allIds = async () => (await prisma.accountDeletionEvent.findMany({ select: { id: true } })).map((row) => row.id);
  const maxId = async () => (await allIds()).reduce((largest, id) => (id > largest ? id : largest), 0n);

  test('a deletion writes one event with every address the account held, as stored, and nothing else about the account', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account([{}, { archived: true }, { keyType: 'EXTERNAL' }]);
    const here = await owner.session();
    await writeStepUpMarker(prisma, 'delete_account', here.id, 'email');
    const before = await maxId();

    const deleted = await deleteAccount(here.cookie);
    expect(deleted.status).toBe(200);
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
    expect(await prisma.ethereumKey.count({ where: { address: { in: owner.addresses } } })).toBe(0);

    const written = await prisma.accountDeletionEvent.findMany({ where: { id: { gt: before } } });
    expect(written).toHaveLength(1);
    expect([...written[0]!.addresses].sort()).toEqual([...owner.addresses].sort());
    expect(Object.keys(written[0]!).sort()).toEqual(['addresses', 'deletedAt', 'id']);
    expect(JSON.stringify(written[0]!, (_key, value) => (typeof value === 'bigint' ? value.toString() : value))).not.toContain(owner.userId);

    const page = await readFeed(before);
    expect(page.events).toHaveLength(1);
    expect(Object.keys(page.events[0]!).sort()).toEqual(['addresses', 'deletedAt', 'id']);
    expect(page.events[0]!.addresses.slice().sort()).toEqual(owner.addresses.slice().sort());
    expect(page.events[0]!.id).toBe(written[0]!.id.toString());
    expect(JSON.stringify(page)).not.toContain(owner.userId);
    expect(JSON.stringify(page)).not.toContain('@example.test');
    expect(page.next).toBe(page.events[0]!.id);
  });

  test('a deletion refused for a stale step-up, a wrong confirmation or a renewing wallet lease writes no event', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const before = await maxId();

    const noStepUp = await account([{}, { keyType: 'EXTERNAL' }]);
    const noStepUpSession = await noStepUp.session();
    expect((await deleteAccount(noStepUpSession.cookie)).status).toBe(403);

    const wrongText = await account();
    const wrongTextSession = await wrongText.session();
    await writeStepUpMarker(prisma, 'delete_account', wrongTextSession.id, 'email');
    expect((await deleteAccount(wrongTextSession.cookie, 'delete my account')).status).toBe(400);

    const leased = await account([{ keyType: 'EXTERNAL' }]);
    const leasedSession = await leased.session();
    await writeStepUpMarker(prisma, 'delete_account', leasedSession.id, 'email');
    await prisma.renewalLease.create({ data: {
      leaseCid: `bafkr4i${'a'.repeat(52)}`, userId: leased.userId, sessionId: null, approvalRequestId: null,
      ownerDid: `did:pkh:eip155:1:${leased.addresses[0]}`, originalCid: `bafkr4ioriginal${'a'.repeat(44)}`, nodeOrigin: 'http://127.0.0.1:9',
      nodeDid: 'did:key:node', renewerDid: 'did:key:renewer', leaseLifetimeSeconds: 3600, approvedAt: new Date(), admittedAt: new Date(),
      leaseExpiresAt: new Date(Date.now() + 3_600_000), grantSiwe: 'the approved grant',
    } });
    const refused = await deleteAccount(leasedSession.cookie);
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'renewal_leases_not_stopped' });

    for (const owner of [noStepUp, wrongText, leased]) {
      expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
      expect(await eventsHolding(owner.addresses[0]!)).toEqual([]);
    }
    expect((await allIds()).filter((id) => id > before)).toEqual([]);
  });

  test('a transaction that rolls back after the event insert leaves no event', async () => {
    const owner = await account([{}, { archived: true }]);
    const before = await maxId();
    await expect(prisma.$transaction(async (transaction) => {
      await recordAccountDeletionEvent(transaction, owner.userId);
      expect((await transaction.accountDeletionEvent.count({ where: { id: { gt: before } } }))).toBe(1);
      throw new Error('the deletion failed after the insert');
    })).rejects.toThrow('the deletion failed after the insert');
    expect(await eventsHolding(owner.addresses[0]!)).toEqual([]);
    expect((await allIds()).filter((id) => id > before)).toEqual([]);
  });

  test('an account with no key address writes no event', async () => {
    const owner = await account([]);
    const before = await maxId();
    await prisma.$transaction((transaction) => recordAccountDeletionEvent(transaction, owner.userId));
    expect((await allIds()).filter((id) => id > before)).toEqual([]);
    // The table itself refuses an empty address list.
    await expect(Promise.resolve(prisma.accountDeletionEvent.create({ data: { addresses: [], deletedAt: new Date() } }))).rejects.toThrow();
  });

  test('the table refuses a NULL address list', async () => {
    const before = await maxId();
    await expect(Promise.resolve(prisma.$executeRaw`INSERT INTO account_deletion_event ("addresses", "deletedAt") VALUES (NULL, now())`)).rejects.toThrow();
    expect((await allIds()).filter((id) => id > before)).toEqual([]);
  });

  test('the advisory lock is taken before the event row is inserted', async () => {
    const owner = await account([{}]);
    const calls: string[] = [];
    await prisma.$transaction(async (transaction) => {
      const recording = new Proxy(transaction, {
        get(target, property, receiver) {
          const value = Reflect.get(target, property, receiver);
          if (property === '$queryRaw') return (...args: unknown[]) => { calls.push('lock'); return (value as (...a: unknown[]) => unknown).apply(target, args); };
          if (property === 'accountDeletionEvent') {
            return new Proxy(value as object, { get: (model, method, modelReceiver) => {
              const member = Reflect.get(model, method, modelReceiver);
              return method === 'create' ? (...args: unknown[]) => { calls.push('insert'); return (member as (...a: unknown[]) => unknown).apply(model, args); } : member;
            } });
          }
          return value;
        },
      });
      await recordAccountDeletionEvent(recording, owner.userId);
    });
    expect(calls).toEqual(['lock', 'insert']);
  });

  test('the feed pages by id, returns an empty page with the cursor it was given, and never exposes a row past `next`', async () => {
    const before = await maxId();
    const first = await account([{}, {}]);
    const second = await account([{ keyType: 'EXTERNAL' }]);
    const third = await account([{ archived: true }]);
    for (const owner of [first, second, third]) await prisma.$transaction((transaction) => recordAccountDeletionEvent(transaction, owner.userId));

    const pageOne = await readFeed(before, 2);
    expect(pageOne.environment).toBe(API);
    expect(pageOne.events.map((event) => event.addresses.slice().sort())).toEqual([first.addresses.slice().sort(), second.addresses]);
    expect(BigInt(pageOne.events[0]!.id)).toBeLessThan(BigInt(pageOne.events[1]!.id));
    expect(pageOne.next).toBe(pageOne.events[1]!.id);

    const pageTwo = await readFeed(pageOne.next, 2);
    expect(pageTwo.events.map((event) => event.addresses)).toEqual([third.addresses]);
    expect(pageTwo.next).toBe(pageTwo.events[0]!.id);

    const empty = await readFeed(pageTwo.next);
    expect(empty).toEqual({ environment: API, events: [], next: pageTwo.next });
  });

  test('the retention sweep removes a 61-day-old row and keeps a 59-day-old one', async () => {
    const { sweepAccountDeletionEventsOnce } = await import('../services/account-deletion-event-sweep');
    const day = 86_400_000;
    const old = await prisma.accountDeletionEvent.create({ data: { addresses: [newAddress()], deletedAt: new Date(Date.now() - 61 * day) } });
    const recent = await prisma.accountDeletionEvent.create({ data: { addresses: [newAddress()], deletedAt: new Date(Date.now() - 59 * day) } });
    expect(await sweepAccountDeletionEventsOnce(prisma)).toBeGreaterThanOrEqual(1);
    expect(await prisma.accountDeletionEvent.findUnique({ where: { id: old.id } })).toBeNull();
    expect(await prisma.accountDeletionEvent.findUnique({ where: { id: recent.id } })).not.toBeNull();
  });

  // Two real connections: PGlite has one, so these run on Postgres only (CI's Postgres leg; locally with OPENKEY_TEST_POSTGRES_URL).
  const postgresOnly = test.skipIf(backend !== 'postgres');
  const settled = async <T>(promise: Promise<T>, ms: number) => Promise.race([promise.then(() => true, () => true), delay(ms).then(() => false)]);

  postgresOnly('a second deletion started while the first is open waits for it: ids commit in order and the feed never skips one', async () => {
    const first = await account([{}]);
    const second = await account([{ keyType: 'EXTERNAL' }]);
    const base = await maxId();

    let firstInserted!: () => void;
    const firstHasInserted = new Promise<void>((resolve) => { firstInserted = resolve; });
    let releaseFirst!: () => void;
    const firstMayCommit = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let secondCommitted = false;

    const firstDeletion = prisma.$transaction(async (transaction) => {
      await recordAccountDeletionEvent(transaction, first.userId);
      firstInserted();
      await firstMayCommit;
    }, { timeout: 60_000 });
    await firstHasInserted;

    // A consumer reads between the stages: the open deletion is invisible, so there is nothing to read.
    const betweenReads = await readFeed(base);
    expect(betweenReads.events).toEqual([]);
    expect(betweenReads.next).toBe(base.toString());

    const secondDeletion = prisma.$transaction(async (transaction) => {
      await recordAccountDeletionEvent(transaction, second.userId);
    }, { timeout: 60_000 }).then(() => { secondCommitted = true; });
    // The second insert is blocked on the advisory lock the first holds, before it has assigned an id.
    const waiting = async () => (await admin!.query(
      `SELECT count(*)::int AS waiting FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
       WHERE l.locktype = 'advisory' AND NOT l.granted AND a.datname = $1`, [databaseName])).rows[0].waiting as number;
    for (let attempt = 0; attempt < 100 && (await waiting()) === 0; attempt++) await delay(50);
    expect(await waiting()).toBe(1);
    expect(await settled(secondDeletion, 300)).toBe(false);
    expect(secondCommitted).toBe(false);
    expect((await readFeed(base)).events).toEqual([]);

    releaseFirst();
    await firstDeletion;
    await secondDeletion;
    expect(secondCommitted).toBe(true);

    const all = await readFeed(base);
    expect(all.events.map((event) => event.addresses)).toEqual([first.addresses, second.addresses]);
    expect(BigInt(all.events[0]!.id)).toBeLessThan(BigInt(all.events[1]!.id));

    // A consumer that read after the first commit and kept `next` still gets the second event.
    const afterFirst = (await readFeed(base, 1));
    expect(afterFirst.events.map((event) => event.addresses)).toEqual([first.addresses]);
    expect((await readFeed(afterFirst.next)).events.map((event) => event.addresses)).toEqual([second.addresses]);
  }, 60_000);

  postgresOnly('without the lock a later deletion commits first, and a cursor past it skips the earlier id for good', async () => {
    const first = newAddress();
    const second = newAddress();
    const base = await maxId();
    let releaseFirst!: () => void;
    const firstMayCommit = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let firstInserted!: () => void;
    const firstHasInserted = new Promise<void>((resolve) => { firstInserted = resolve; });
    const firstInsert = prisma.$transaction(async (transaction) => {
      await transaction.accountDeletionEvent.create({ data: { addresses: [first], deletedAt: new Date() } });
      firstInserted();
      await firstMayCommit;
    }, { timeout: 60_000 });
    await firstHasInserted;
    await prisma.$transaction((transaction) => transaction.accountDeletionEvent.create({ data: { addresses: [second], deletedAt: new Date() } }));
    const read = await readFeed(base);
    expect(read.events.map((event) => event.addresses)).toEqual([[second]]);
    releaseFirst();
    await firstInsert;
    // The earlier id committed after the cursor moved past the later one: the consumer never sees it.
    expect((await readFeed(read.next)).events).toEqual([]);
    expect((await eventsHolding(first)).length).toBe(1);
  }, 60_000);
}
