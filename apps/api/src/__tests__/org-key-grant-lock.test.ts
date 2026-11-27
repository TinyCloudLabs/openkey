import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Client } from 'pg';

// TC-1518 F3: signing takes FOR SHARE on the grant row inside its transaction, and
// revocation is an UPDATE on the same row. The two must not interleave. Runs against
// a real Postgres (OPENKEY_TEST_POSTGRES_URL) in a throwaway schema built from the
// tracked migration chain.
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '../../../..');

// Same predicate as the grant lock in services/org-keys.ts (signing transaction).
const LOCK_GRANT_SQL = `SELECT id, role FROM "key_grants"
  WHERE id = $1 AND "keyId" = $2 AND "granteeUserId" = $3 AND "revokedAt" IS NULL
  FOR SHARE`;
const REVOKE_GRANT_SQL = `UPDATE "key_grants" SET "revokedAt" = now() WHERE id = $1`;

const sealingContext = `${'0'.repeat(42)}A`;

// Waits for a real Postgres condition: the backend is parked on a lock. This polls
// pg_stat_activity rather than sleeping for a guessed duration, and fails if the
// backend never blocks.
async function waitUntilLockWaiting(observer: Client, pid: number) {
  for (let attempt = 0; attempt < 500; attempt++) {
    const row = await observer.query<{ wait_event_type: string | null }>(
      `SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1`,
      [pid],
    );
    if (row.rows[0]?.wait_event_type === 'Lock') return;
    await Bun.sleep(5);
  }
  throw new Error(`backend ${pid} never waited on a lock`);
}

describe.skipIf(!postgresUrl)('org key grant lock (TC-1518 F3, real Postgres)', () => {
  const schema = `tc1518_f3_${randomUUID().replaceAll('-', '')}`;
  const clients: Client[] = [];
  let admin: Client;
  const keyId = 'org-key-f3';
  const revokedFirst = 'grant-f3-a';
  const revokedSecond = 'grant-f3-b';

  async function connect(): Promise<{ client: Client; pid: number }> {
    const client = new Client({ connectionString: postgresUrl });
    await client.connect();
    await client.query(`SET search_path TO "${schema}"`);
    clients.push(client);
    const { rows } = await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
    return { client, pid: rows[0]!.pid };
  }

  beforeAll(async () => {
    ({ client: admin } = await connect());
    await admin.query(`CREATE SCHEMA "${schema}"`);
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
  });

  afterAll(async () => {
    for (const client of clients) await client.end().catch(() => undefined);
    const cleanup = new Client({ connectionString: postgresUrl });
    await cleanup.connect();
    await cleanup.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await cleanup.end();
  });

  test('a revoke waits for an in-flight signing transaction to commit', async () => {
    const signer = await connect();
    const revoker = await connect();

    await signer.client.query('BEGIN');
    const locked = await signer.client.query(LOCK_GRANT_SQL, [revokedFirst, keyId, 'owner-a']);
    expect(locked.rows).toHaveLength(1);

    await revoker.client.query('BEGIN');
    const revoke = revoker.client.query(REVOKE_GRANT_SQL, [revokedFirst]);
    await waitUntilLockWaiting(admin, revoker.pid);

    await signer.client.query('COMMIT');
    await revoke;
    await revoker.client.query('COMMIT');

    const after = await admin.query<{ revokedAt: Date | null }>(
      `SELECT "revokedAt" FROM "key_grants" WHERE id = $1`,
      [revokedFirst],
    );
    expect(after.rows[0]?.revokedAt).not.toBeNull();
  });

  test('a signing transaction that starts during an uncommitted revoke sees the revoke and refuses', async () => {
    const revoker = await connect();
    const signer = await connect();

    await revoker.client.query('BEGIN');
    await revoker.client.query(REVOKE_GRANT_SQL, [revokedSecond]);

    await signer.client.query('BEGIN');
    const lock = signer.client.query(LOCK_GRANT_SQL, [revokedSecond, keyId, 'owner-a']);
    await waitUntilLockWaiting(admin, signer.pid);

    await revoker.client.query('COMMIT');
    const result = await lock;
    await signer.client.query('ROLLBACK');
    expect(result.rows).toHaveLength(0);
  });
});
