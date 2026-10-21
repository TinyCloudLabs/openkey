import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Client } from 'pg';
import { createPrismaClient } from '@openkey/db';
import type { Prisma, PrismaClient } from '@openkey/db';
import { lockActiveGrant } from '../services/org-keys';

// Real-Postgres coverage for the grant lock that signing takes (TC-1518 F3, F-C).
// The signing side calls the production lockActiveGrant. The revoke side writes
// through Prisma, the same path a revoke uses. Raw SQL is limited to schema setup
// and lock-wait observation. Runs when OPENKEY_TEST_POSTGRES_URL is set; in CI the
// URL is required, so a missing URL fails the run instead of skipping it.
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '../../../..');

if (process.env.CI && !postgresUrl) {
  test('OPENKEY_TEST_POSTGRES_URL is set in CI', () => {
    throw new Error('OPENKEY_TEST_POSTGRES_URL is required in CI so the grant-lock tests run against Postgres');
  });
}

const sealingContext = `${'0'.repeat(42)}A`;

// Waits for a real Postgres condition: the backend is parked on a lock. This polls
// pg_stat_activity rather than sleeping for a guessed duration, and fails if the
// backend never blocks.
async function waitUntilLockWaiting(observer: Client, pid: number) {
  for (let attempt = 0; attempt < 500; attempt++) {
    const row = await observer.query<{ wait_event_type: string | null }>(
      'SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1',
      [pid],
    );
    if (row.rows[0]?.wait_event_type === 'Lock') return;
    // Real-time poll on purpose: the lock wait happens in a separate Postgres backend,
    // which fake timers in this process cannot advance.
    await Bun.sleep(5);
  }
  throw new Error(`backend ${pid} never waited on a lock`);
}

async function backendPid(tx: Prisma.TransactionClient): Promise<number> {
  const [row] = await tx.$queryRaw<{ pid: number }[]>`SELECT pg_backend_pid() AS pid`;
  if (!row) throw new Error('pg_backend_pid returned no row');
  return row.pid;
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe.skipIf(!postgresUrl)('org key grant lock (TC-1518 F3, real Postgres)', () => {
  const schema = `tc1518_f3_${randomUUID().replaceAll('-', '')}`;
  const keyId = 'org-key-f3';
  const revokedFirst = 'grant-f3-a';
  const revokedSecond = 'grant-f3-b';
  let admin: Client;
  let prisma: PrismaClient;

  beforeAll(async () => {
    admin = new Client({ connectionString: postgresUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.query(`SET search_path TO "${schema}"`);
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
    for (const migration of migrations) {
      await admin.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
    await admin.query(`INSERT INTO "user" ("id", "email", "updatedAt") VALUES ('owner-a', 'owner-a@example.test', now())`);
    await admin.query(
      `INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealingContext", "keyType", "custody", "isCanonicalTinyCloud")
       VALUES ($1, NULL, '0x00000000000000000000000000000000000000f3', 'pk', $2, 'MANAGED', 'ORG', false)`,
      [keyId, sealingContext],
    );
    await admin.query(
      `INSERT INTO "org_keys" ("keyId", "orgId", "orgName", "controllerDid") VALUES ($1, 'org-f3', 'Org F3', 'did:pkh:eip155:1:0x0')`,
      [keyId],
    );
    // Two grants so each test revokes its own row. Only one active OWNER per key is
    // allowed, so the second one is an ADMIN grant on the same key.
    await admin.query(
      `INSERT INTO "key_grants" ("id", "keyId", "role", "granteeUserId") VALUES ($1, $2, 'OWNER', 'owner-a'), ($3, $2, 'ADMIN', 'owner-a')`,
      [revokedFirst, keyId, revokedSecond],
    );
    prisma = createPrismaClient({ connectionString: postgresUrl, schema });
    // Applying every migration is not a fast path; the default 5s hook timeout is too
    // tight when the suite runs against the same Postgres in parallel. Not a sleep.
  }, 60_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    await admin?.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
    await admin?.end();
  });

  test('a revoke waits for an in-flight signing transaction to commit', async () => {
    const locked = deferred();
    const release = deferred();
    const signing = prisma.$transaction(async (tx) => {
      const grant = await lockActiveGrant(tx, { grantId: revokedFirst, keyId, userId: 'owner-a' });
      locked.resolve();
      await release.promise;
      return grant;
    });
    await locked.promise;

    const revoking = prisma.$transaction(async (tx) => {
      const pid = await backendPid(tx);
      // Prisma queries run on then(); Promise.resolve starts this one without awaiting it.
      const update = Promise.resolve(
        tx.keyGrant.update({ where: { id: revokedFirst }, data: { revokedAt: new Date() } }),
      );
      try {
        await waitUntilLockWaiting(admin, pid);
      } finally {
        release.resolve();
      }
      await update;
    });

    await Promise.all([signing, revoking]);
    expect(await signing).toEqual({ id: revokedFirst, role: 'OWNER' });

    const after = await admin.query<{ revokedAt: Date | null }>(
      `SELECT "revokedAt" FROM "key_grants" WHERE id = $1`,
      [revokedFirst],
    );
    expect(after.rows[0]?.revokedAt).not.toBeNull();
  });

  test('a signing transaction that starts during an uncommitted revoke sees the revoke and refuses', async () => {
    const revokeWritten = deferred();
    const commitRevoke = deferred();
    const revoking = prisma.$transaction(async (tx) => {
      await tx.keyGrant.update({ where: { id: revokedSecond }, data: { revokedAt: new Date() } });
      revokeWritten.resolve();
      await commitRevoke.promise;
    });
    await revokeWritten.promise;

    const signing = prisma.$transaction(async (tx) => {
      const pid = await backendPid(tx);
      const lock = lockActiveGrant(tx, { grantId: revokedSecond, keyId, userId: 'owner-a' });
      try {
        await waitUntilLockWaiting(admin, pid);
      } finally {
        commitRevoke.resolve();
      }
      return lock;
    });

    expect(await signing).toBeNull();
    await revoking;
  });
});
