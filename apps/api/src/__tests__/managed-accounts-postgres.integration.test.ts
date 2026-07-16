import { afterAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { readFile, readdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { Client } from 'pg';

const migrationNames = [
  '0_init',
  '20260303_add_user_encryption_key',
  '20260628_add_auto_sign_enabled',
  '20260630_add_tinycloud_bootstrap_state',
  '20260714_origin_main_schema_catchup',
  '20260715_0001_managed_accounts_phase_a_fix',
  '20260715_0002_managed_accounts_registration_api',
  '20260715_0003_managed_accounts_eject_api',
  '20260715_0004_managed_accounts_webhooks',
] as const;

const migrationSql = new Map<string, Promise<string>>(
  migrationNames.map((name) => [name, readFile(`packages/db/prisma/migrations/${name}/migration.sql`, 'utf8')]),
);

type SqlExecutor = { exec(sql: string): Promise<unknown>; query<T = unknown>(sql: string): Promise<{ rows: T[] }> };

async function applyMigrations(db: SqlExecutor, through: number = migrationNames.length) {
  for (const name of migrationNames.slice(0, through)) await db.exec(await migrationSql.get(name)!);
}

async function applyMigrationsFrom(db: SqlExecutor, from: number) {
  for (const name of migrationNames.slice(from)) await db.exec(await migrationSql.get(name)!);
}

async function expectRejected(fn: () => Promise<unknown>) {
  let rejected = false;
  try { await fn(); } catch { rejected = true; }
  expect(rejected).toBe(true);
}

const timestamp = '2026-07-15T12:00:00.000Z';
const seedSql = `
INSERT INTO "user" ("id", "email", "updatedAt") VALUES ('u1', 'u1@example.test', '${timestamp}'), ('u2', 'u2@example.test', '${timestamp}');
INSERT INTO "passkey" ("id", "userId", "publicKey", "credentialID", "deviceType", "backedUp", "createdAt") VALUES ('pk1', 'u1', 'public-key', 'credential-1', 'singleDevice', false, '${timestamp}');
INSERT INTO "organization" ("id", "name", "updatedAt") VALUES ('o1', 'Org 1', '${timestamp}'), ('o2', 'Org 2', '${timestamp}');
INSERT INTO "organization_membership" ("id", "organizationId", "userId", "validFrom") VALUES ('m1', 'o1', 'u1', '${timestamp}');
INSERT INTO "plan_entitlements" ("id", "organizationId", "maxApps", "maxOrganizationMembers", "maxManagedAccounts", "monthlyActiveManagedUsers", "storageBytesPerManagedAccount", "requestsPerMinute", "maxTenantDelegationTtlSeconds", "maxTenantPolicyVersion", "auditRetentionDays", "updatedAt") VALUES ('p1', 'o1', 3, 3, 3, 3, 1000, 10, 3600, 1, 30, '${timestamp}');
INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES
  ('k1', 'u1', '0x0000000000000000000000000000000000000001', '0x1', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ');
INSERT INTO "managed_account" ("id", "ownerUserId", "organizationId", "externalUserId", "keyId", "updatedAt") VALUES ('a1', 'u1', 'o1', 'external-1', 'k1', '${timestamp}');
`;

async function exerciseConstraints(db: SqlExecutor) {
  await db.exec(seedSql);

  // A raw activation without the owner's persisted passkey is rejected at COMMIT.
  await db.exec(`INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES ('k0', 'u2', '0x0000000000000000000000000000000000000010', '0x10', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCQ');`);
  await db.exec(`INSERT INTO "managed_account" ("id", "ownerUserId", "organizationId", "externalUserId", "keyId", "updatedAt") VALUES ('a0', 'u2', 'o1', 'external-no-passkey', 'k0', '${timestamp}');`);
  await expectRejected(() => db.exec(`BEGIN; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c0', 'a0', 'ORGANIZATION', 'o1', 1, '${timestamp}'); UPDATE "managed_account" SET "state" = 'MANAGED', "custodyEpoch" = 1, "custodyHeadId" = 'c0' WHERE "id" = 'a0'; COMMIT;`));
  await db.exec('ROLLBACK').catch(() => undefined);

  // The coherent initial transition is the only legal way to create an active head.
  await db.exec(`BEGIN; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c1', 'a1', 'ORGANIZATION', 'o1', 1, '${timestamp}'); INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('e1', 'a1', 'k1', 1, 'hash-1', 'none', 'organization:o1', 'INITIAL_ACTIVATION', 'policy', 'signature-1', '${timestamp}'); UPDATE "managed_account" SET "state" = 'MANAGED', "custodyEpoch" = 1, "custodyHeadId" = 'c1' WHERE "id" = 'a1'; COMMIT;`);
  const active = await db.query<{ state: string; custodyEpoch: number }>(`SELECT "state", "custodyEpoch" FROM "managed_account" WHERE "id" = 'a1'`);
  expect(active.rows[0]).toEqual({ state: 'MANAGED', custodyEpoch: 1 });

  // The exact organization-to-itself epoch-2 transaction from Sol's review
  // must fail rather than create a second organization custody epoch.
  await expectRejected(() => db.exec(`BEGIN; UPDATE "key_custody" SET "revokedAt" = '${timestamp}' WHERE "id" = 'c1'; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c2-org', 'a1', 'ORGANIZATION', 'o1', 2, '${timestamp}'); INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "previousEventHash", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('e2-org', 'a1', 'k1', 2, 'hash-1', 'hash-2-org', 'organization:o1', 'organization:o1', 'RAW_ROTATION', 'policy', 'signature-2-org', '${timestamp}'); UPDATE "managed_account" SET "custodyEpoch" = 2, "custodyHeadId" = 'c2-org' WHERE "id" = 'a1'; COMMIT;`));
  await db.exec('ROLLBACK').catch(() => undefined);
  const afterOrganizationRotation = await db.query<{ state: string; custodyEpoch: number; custodyHeadId: string; custodyCount: number; eventCount: number }>(`SELECT ma."state", ma."custodyEpoch", ma."custodyHeadId", (SELECT count(*)::int FROM "key_custody" WHERE "managedAccountId" = ma."id") AS "custodyCount", (SELECT count(*)::int FROM "possession_event" WHERE "managedAccountId" = ma."id") AS "eventCount" FROM "managed_account" ma WHERE ma."id" = 'a1'`);
  expect(afterOrganizationRotation.rows[0]).toEqual({ state: 'MANAGED', custodyEpoch: 1, custodyHeadId: 'c1', custodyCount: 1, eventCount: 1 });

  // The signing barrier may be entered and safely recovered before custody
  // changes; arbitrary lifecycle jumps remain rejected at the database edge.
  await db.exec(`UPDATE "managed_account" SET "state" = 'EJECTING' WHERE "id" = 'a1'`);
  await db.exec(`UPDATE "managed_account" SET "state" = 'MANAGED' WHERE "id" = 'a1'`);
  await expectRejected(() => db.exec(`UPDATE "managed_account" SET "state" = 'USER_OWNED' WHERE "id" = 'a1'`));
  await db.exec('ROLLBACK').catch(() => undefined);

  // A signing failure before mutation and an event/write failure after two
  // mutations both roll back the executable transaction, preserving epoch 1.
  try { await db.exec(`BEGIN; SELECT 1 / 0; COMMIT;`); } catch { await db.exec('ROLLBACK'); }
  try {
    await db.exec(`BEGIN; UPDATE "key_custody" SET "revokedAt" = '${timestamp}' WHERE "id" = 'c1'; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c2', 'a1', 'USER', 'u1', 2, '${timestamp}'); UPDATE "managed_account" SET "state" = 'USER_OWNED', "custodyEpoch" = 2, "custodyHeadId" = 'c2' WHERE "id" = 'a1'; COMMIT;`);
  } catch { await db.exec('ROLLBACK'); }
  const rollbackState = await db.query<{ revokedAt: string | null; count: number }>(`SELECT "revokedAt", (SELECT count(*)::int FROM "key_custody" WHERE "managedAccountId" = 'a1') AS count FROM "key_custody" WHERE "id" = 'c1'`);
  expect(rollbackState.rows[0]).toEqual({ revokedAt: null, count: 1 });

  // A canonical-field change in the epoch-2 event is rejected at deferred
  // commit, even when the custody row and predecessor are otherwise valid.
  await expectRejected(() => db.exec(`BEGIN; UPDATE "key_custody" SET "revokedAt" = '${timestamp}' WHERE "id" = 'c1'; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c2-wrong', 'a1', 'USER', 'u1', 2, '${timestamp}'); INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "previousEventHash", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('e2-wrong', 'a1', 'k1', 2, 'hash-1', 'hash-2-wrong', 'organization:o1', 'user:u1', 'WRONG_REASON', 'policy', 'signature-2-wrong', '${timestamp}'); UPDATE "managed_account" SET "state" = 'USER_OWNED', "custodyEpoch" = 2, "custodyHeadId" = 'c2-wrong' WHERE "id" = 'a1'; COMMIT;`));
  await db.exec('ROLLBACK').catch(() => undefined);

  // A complete eject transition must include the epoch-2 event and predecessor.
  await expectRejected(() => db.exec(`BEGIN; UPDATE "key_custody" SET "revokedAt" = '${timestamp}' WHERE "id" = 'c1'; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c2', 'a1', 'USER', 'u1', 2, '${timestamp}'); UPDATE "managed_account" SET "state" = 'USER_OWNED', "custodyEpoch" = 2, "custodyHeadId" = 'c2' WHERE "id" = 'a1'; COMMIT;`));
  await db.exec('ROLLBACK').catch(() => undefined);
  await db.exec(`BEGIN; UPDATE "key_custody" SET "revokedAt" = '${timestamp}' WHERE "id" = 'c1'; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c2', 'a1', 'USER', 'u1', 2, '${timestamp}'); INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "previousEventHash", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('e2', 'a1', 'k1', 2, 'hash-1', 'hash-2', 'organization:o1', 'user:u1', 'OWNER_REQUEST', 'policy', 'signature-2', '${timestamp}'); UPDATE "managed_account" SET "state" = 'USER_OWNED', "custodyEpoch" = 2, "custodyHeadId" = 'c2' WHERE "id" = 'a1'; COMMIT;`);
  await db.exec(`UPDATE "possession_event" SET "witnessReceipt" = '{"checkpoint":"user-owned"}'::jsonb WHERE "id" = 'e2'`);
  const witness = await db.query<{ checkpoint: string }>(`SELECT "witnessReceipt"->>'checkpoint' AS checkpoint FROM "possession_event" WHERE "id" = 'e2'`);
  expect(witness.rows[0]).toEqual({ checkpoint: 'user-owned' });
  await db.exec(`INSERT INTO "managed_account_node" ("id", "managedAccountId", "nodeId", "baseUrl", "role") VALUES ('node-row-1', 'a1', 'node-1', 'https://node.example', 'HOST')`);
  await db.exec(`INSERT INTO "eject_revocation_receipt" ("id", "possessionEventId", "nodeId", "managedAccountId", "tenantParentDelegationCid") VALUES ('receipt-1', 'e2', 'node-row-1', 'a1', 'bafy-parent')`);
  await expectRejected(() => db.exec(`UPDATE "possession_event" SET "id" = 'e2-mutated' WHERE "id" = 'e2'`));
  const eventIdentity = await db.query<{ eventId: string; receiptEventId: string }>(`SELECT pe."id" AS "eventId", er."possessionEventId" AS "receiptEventId" FROM "possession_event" pe JOIN "eject_revocation_receipt" er ON er."possessionEventId" = pe."id" WHERE pe."id" = 'e2'`);
  expect(eventIdentity.rows[0]).toEqual({ eventId: 'e2', receiptEventId: 'e2' });
  await expectRejected(() => db.exec(`UPDATE "possession_event" SET "reason" = 'MUTATED' WHERE "id" = 'e2'`));
  await expectRejected(() => db.exec(`DELETE FROM "possession_event" WHERE "id" = 'e2'`));
  await expectRejected(() => db.exec(`UPDATE "managed_account" SET "keyId" = 'kq' WHERE "id" = 'a1'`));
  await expectRejected(() => db.exec(`UPDATE "managed_account" SET "ownerUserId" = 'u2' WHERE "id" = 'a1'`));
  await expectRejected(() => db.exec(`UPDATE "managed_account" SET "organizationId" = 'o2' WHERE "id" = 'a1'`));
  await expectRejected(() => db.exec(`UPDATE "managed_account" SET "externalUserId" = 'changed' WHERE "id" = 'a1'`));
  await expectRejected(() => db.exec(`UPDATE "ethereum_keys" SET "address" = '0x0000000000000000000000000000000000000098' WHERE "id" = 'k1'`));
  await expectRejected(() => db.exec(`UPDATE "ethereum_keys" SET "publicKey" = 'changed' WHERE "id" = 'k1'`));

  // USER_OWNED is terminal: even the complete reverse transaction (revoke
  // the user head, append organization custody and its event, then restore
  // the account head/state) must fail and leave epoch 2 untouched.
  await expectRejected(() => db.exec(`BEGIN; UPDATE "key_custody" SET "revokedAt" = '${timestamp}' WHERE "id" = 'c2'; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c3', 'a1', 'ORGANIZATION', 'o1', 3, '${timestamp}'); INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "previousEventHash", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('e3', 'a1', 'k1', 3, 'hash-2', 'hash-3', 'user:u1', 'organization:o1', 'RESTORE', 'policy', 'signature-3', '${timestamp}'); UPDATE "managed_account" SET "state" = 'MANAGED', "custodyEpoch" = 3, "custodyHeadId" = 'c3' WHERE "id" = 'a1'; COMMIT;`));
  await db.exec('ROLLBACK').catch(() => undefined);
  const terminal = await db.query<{ state: string; custodyEpoch: number; custodyHeadId: string; custodianType: string; custodyCount: number; eventCount: number }>(`SELECT ma."state", ma."custodyEpoch", ma."custodyHeadId", kc."custodianType", (SELECT count(*)::int FROM "key_custody" WHERE "managedAccountId" = ma."id") AS "custodyCount", (SELECT count(*)::int FROM "possession_event" WHERE "managedAccountId" = ma."id") AS "eventCount" FROM "managed_account" ma JOIN "key_custody" kc ON kc."id" = ma."custodyHeadId" WHERE ma."id" = 'a1'`);
  expect(terminal.rows[0]).toEqual({ state: 'USER_OWNED', custodyEpoch: 2, custodyHeadId: 'c2', custodianType: 'USER', custodyCount: 2, eventCount: 2 });

  // Q is one of the sixteen valid canonical final base64url characters.
  await db.exec(`INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES ('kq', 'u1', '0x0000000000000000000000000000000000000002', '0x2', 'sealed', 'MANAGED', 'PERSONAL', 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ')`);
  // Legacy external rows are retained, but cannot be relabeled into managed custody.
  await db.exec(`INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose") VALUES ('ke', 'u1', '0x0000000000000000000000000000000000000003', '0x3', NULL, 'EXTERNAL', 'PERSONAL')`);
  await expectRejected(() => db.exec(`UPDATE "ethereum_keys" SET "keyType" = 'MANAGED' WHERE "id" = 'ke'`));
  await expectRejected(() => db.exec(`UPDATE "ethereum_keys" SET "keyPurpose" = 'PERSONAL' WHERE "id" = 'k1'`));
  await expectRejected(() => db.exec(`INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES ('kn', 'u1', '0x0000000000000000000000000000000000000004', '0x4', 'sealed', 'MANAGED', 'PERSONAL', 'not-canonical')`));

  // Gaps, revoked heads, wrong heads, and history mutations fail closed.
  await expectRejected(() => db.exec(`UPDATE "managed_account" SET "custodyEpoch" = 3, "custodyHeadId" = 'c1' WHERE "id" = 'a1'`));
  await expectRejected(() => db.exec(`UPDATE "key_custody" SET "custodianId" = 'other' WHERE "id" = 'c1'`));
  await expectRejected(() => db.exec(`DELETE FROM "key_custody" WHERE "id" = 'c1'`));
  await expectRejected(() => db.exec(`INSERT INTO "possession_event" ("id", "managedAccountId", "epoch", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('unsigned', 'a1', 2, 'hash-unsigned', 'x', 'y', 'x', 'x', '', '${timestamp}')`));
  await expectRejected(() => db.exec(`INSERT INTO "organization_membership" ("id", "organizationId", "userId", "status", "validFrom", "revokedAt") VALUES ('bad-membership', 'o1', 'u1', 'ACTIVE', '${timestamp}', '${timestamp}')`));
}

describe('managed-account migrations and executable constraints', () => {
  let pglite: PGlite;

  test('fresh install executes every migration and exercises constraints', async () => {
    const migrationsOnDisk = (await readdir('packages/db/prisma/migrations', { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
    expect(migrationsOnDisk).toEqual([...migrationNames]);
    pglite = new PGlite('memory://');
    await applyMigrations(pglite);
    await exerciseConstraints(pglite);
  });

  test('origin/main schema upgrades through the managed-account migration', async () => {
    const upgrade = new PGlite('memory://');
    const originMigrationCount = migrationNames.indexOf('20260714_origin_main_schema_catchup') + 1;
    await applyMigrations(upgrade, originMigrationCount);
    const originTables = await upgrade.query<{ table_name: string }>(`SELECT table_name FROM information_schema.tables WHERE table_name IN ('developer_account', 'oauth_daily_stats') ORDER BY table_name`);
    expect(originTables.rows.map((row) => row.table_name)).toEqual(['developer_account', 'oauth_daily_stats']);
    await upgrade.exec(`INSERT INTO "user" ("id", "email", "updatedAt") VALUES ('legacy-user', 'legacy@example.test', '${timestamp}'); INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType") VALUES ('legacy-null', 'legacy-user', '0x0000000000000000000000000000000000000099', '0x99', NULL, 'EXTERNAL')`);
    await applyMigrationsFrom(upgrade, originMigrationCount);
    // The legacy row is usable through the legacy derivation path, but its
    // NULL marker can never be converted into a new derivation context.
    await expectRejected(() => upgrade.exec(`UPDATE "ethereum_keys" SET "sealingContext" = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ' WHERE "id" = 'legacy-null'`));
    await exerciseConstraints(upgrade);
    await upgrade.close();
  });

  afterAll(async () => { await pglite?.close(); });
});

const externalUrl = process.env.MIGRATION_DATABASE_URL ?? (
  process.env.DATABASE_URL && !process.env.DATABASE_URL.startsWith('pglite:') ? process.env.DATABASE_URL : undefined
);

test.skipIf(!externalUrl)('the same executable migration suite runs against configured PostgreSQL', async () => {
  const client = new Client({ connectionString: externalUrl });
  const schema = `openkey_migration_${randomUUID().replaceAll('-', '')}`;
  await client.connect();
  try {
    await client.query(`CREATE SCHEMA "${schema}"`);
    await client.query(`SET search_path TO "${schema}"`);
    const db: SqlExecutor = {
      exec: async (sql) => { await client.query(sql); },
      query: async <T>(sql: string) => client.query(sql) as unknown as Promise<{ rows: T[] }>,
    };
    await applyMigrations(db);
    await exerciseConstraints(db);
  } finally {
    await client.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
    await client.end();
  }
}, 30_000);

test.skipIf(!externalUrl)('PostgreSQL two-connection custody barrier serializes and rolls back safely', async () => {
  const first = new Client({ connectionString: externalUrl });
  const second = new Client({ connectionString: externalUrl });
  const schema = `openkey_contention_${randomUUID().replaceAll('-', '')}`;
  await first.connect();
  await second.connect();
  try {
    await first.query(`CREATE SCHEMA "${schema}"`);
    await first.query(`SET search_path TO "${schema}"`);
    await second.query(`SET search_path TO "${schema}"`);
    const db: SqlExecutor = {
      exec: async (sql) => { await first.query(sql); },
      query: async <T>(sql: string) => first.query(sql) as unknown as Promise<{ rows: T[] }>,
    };
    await applyMigrations(db);
    await db.exec(seedSql);
    await db.exec(`BEGIN; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c1', 'a1', 'ORGANIZATION', 'o1', 1, '${timestamp}'); INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('e1', 'a1', 'k1', 1, 'hash-1', 'none', 'organization:o1', 'INITIAL_ACTIVATION', 'policy', 'signature-1', '${timestamp}'); UPDATE "managed_account" SET "state" = 'MANAGED', "custodyEpoch" = 1, "custodyHeadId" = 'c1' WHERE "id" = 'a1'; COMMIT;`);

    await first.query('BEGIN');
    await first.query(`SELECT "id" FROM "managed_account" WHERE "id" = 'a1' FOR UPDATE`);
    let secondAcquired = false;
    const waiting = second.query(`BEGIN; SELECT "id" FROM "managed_account" WHERE "id" = 'a1' FOR UPDATE`).then(() => { secondAcquired = true; });
    await new Promise((resolve) => setTimeout(resolve, 75));
    expect(secondAcquired).toBe(false);
    await first.query('UPDATE "key_custody" SET "revokedAt" = $1 WHERE "id" = $2', [timestamp, 'c1']);
    await first.query('ROLLBACK');
    await waiting;
    const afterRollback = await second.query<{ revokedAt: string | null }>(`SELECT "revokedAt" FROM "key_custody" WHERE "id" = 'c1'`);
    expect(afterRollback.rows[0]?.revokedAt).toBeNull();
    await second.query('COMMIT');
  } finally {
    await first.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
    await second.end();
    await first.end();
  }
}, 30_000);
