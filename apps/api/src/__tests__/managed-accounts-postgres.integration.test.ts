import { afterAll, beforeAll, describe, expect, mock, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { readFile, readdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { Client } from 'pg';
import { PrismaPGlite } from 'pglite-prisma-adapter';

let createPrismaClient: typeof import('@openkey/db')['createPrismaClient'];
let PrismaClient: typeof import('@openkey/db')['PrismaClient'];
let createTenantManagedAccount: typeof import('../services/tenant-managed-accounts')['createTenantManagedAccount'];
let listTenantManagedAccounts: typeof import('../services/tenant-managed-accounts')['listTenantManagedAccounts'];
let createTeeClient: typeof import('@openkey/tee')['createTeeClient'];
let issueOrganizationCredential: typeof import('../services/organization-credentials')['issueOrganizationCredential'];
let authenticateOrganizationCredential: typeof import('../services/organization-credentials')['authenticateOrganizationCredential'];
type ManagementActor = Omit<Awaited<ReturnType<typeof authenticateOrganizationCredential>>, 'kind'> & {
  kind: 'MANAGEMENT';
};

beforeAll(async () => {
  // These are production-code integration tests. Bun shares its module cache
  // between test files, so load fresh production package/service graphs after
  // clearing boundary mocks installed by route-unit tests.
  mock.restore();
  const dbPath = '../../../../packages/db/src/index?__fresh=postgres-integration';
  const db = await import(dbPath);
  createPrismaClient = db.createPrismaClient;
  PrismaClient = db.PrismaClient;
  mock.module('@openkey/db', () => ({ ...db }));

  const teePath = '../../../../packages/tee/src/index?__fresh=postgres-integration';
  const tee = await import(teePath);
  createTeeClient = tee.createTeeClient;
  mock.module('@openkey/tee', () => ({ ...tee }));

  const servicePath = '../services/tenant-managed-accounts?__fresh=postgres-integration';
  const service = await import(servicePath);
  createTenantManagedAccount = service.createTenantManagedAccount;
  listTenantManagedAccounts = service.listTenantManagedAccounts;

  const credentialsPath = '../services/organization-credentials?__fresh=postgres-integration';
  const credentials = await import(credentialsPath);
  issueOrganizationCredential = credentials.issueOrganizationCredential;
  authenticateOrganizationCredential = credentials.authenticateOrganizationCredential;
});

afterAll(() => {
  mock.restore();
});

const migrationNames = [
  '0_init',
  '20260303_add_user_encryption_key',
  '20260628_add_auto_sign_enabled',
  '20260630_add_tinycloud_bootstrap_state',
  '20260714_origin_main_schema_catchup',
  '20260714_zz_origin_main_db_push_reconciliation',
  '20260715_0001_managed_accounts_phase_a_fix',
  '20260715_0002_managed_accounts_registration_api',
  '20260715_0003_managed_accounts_eject_api',
  '20260715_0004_managed_accounts_webhooks',
  '20260720_0001_tenant_managed_email_accounts',
  '20260720_0002_management_credential_default',
  '20260720_0003_tenant_managed_account_guard_fixes',
  '20260720_0004_drop_registration_intent',
  '20260721_0001_better_auth_1_6_oauth_refresh_tokens',
  '20260728_0001_oauth_tenant_lifecycle_guard',
  '20260728_0002_coordinationos_session_grants',
  '20260730_0001_oauth_client_tinycloud_session_policy',
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
const sealingContext = (seed: string) => `${seed.repeat(42).slice(0, 42)}Q`;
const contextA = sealingContext('A');
const contextB = sealingContext('B');
const contextC = sealingContext('C');
const contextD = sealingContext('D');
const seedSql = `
INSERT INTO "user" ("id", "email", "updatedAt") VALUES ('u1', 'u1@example.test', '${timestamp}'), ('u2', 'u2@example.test', '${timestamp}'), ('u3', 'u3@example.test', '${timestamp}');
INSERT INTO "passkey" ("id", "userId", "publicKey", "credentialID", "deviceType", "backedUp", "createdAt") VALUES ('pk1', 'u1', 'public-key', 'credential-1', 'singleDevice', false, '${timestamp}');
INSERT INTO "organization" ("id", "name", "updatedAt") VALUES ('o1', 'Org 1', '${timestamp}'), ('o2', 'Org 2', '${timestamp}');
INSERT INTO "organization_membership" ("id", "organizationId", "userId", "validFrom") VALUES ('m1', 'o1', 'u1', '${timestamp}');
INSERT INTO "plan_entitlements" ("id", "organizationId", "maxApps", "maxOrganizationMembers", "maxManagedAccounts", "monthlyActiveManagedUsers", "storageBytesPerManagedAccount", "requestsPerMinute", "maxTenantDelegationTtlSeconds", "maxTenantPolicyVersion", "auditRetentionDays", "updatedAt") VALUES ('p1', 'o1', 3, 3, 3, 3, 1000, 10, 3600, 1, 30, '${timestamp}');
INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES
  ('k1', 'u1', '0x0000000000000000000000000000000000000001', '0x1', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', '${contextA}');
INSERT INTO "managed_account" ("id", "ownerUserId", "organizationId", "subjectEmail", "externalUserId", "keyId", "updatedAt") VALUES ('a1', 'u1', 'o1', 'u1@example.test', 'external-1', 'k1', '${timestamp}');
`;

async function exerciseConstraints(db: SqlExecutor) {
  await db.exec(seedSql);

  await db.exec(`INSERT INTO "oauth_client" ("id", "clientId", "name", "redirectUris", "scopes", "contacts", "tinycloudSessionPolicy", "tinycloudSessionOrigin", "updatedAt") VALUES ('oc1', 'ok_policy_client', 'Policy Client', ARRAY['https://app.example/cb'], ARRAY['openid'], ARRAY[]::text[], 'coordinationos-kv-v1', 'https://app.example', '${timestamp}')`);
  await expectRejected(() => db.exec(`UPDATE "oauth_client" SET "tinycloudSessionOrigin" = NULL WHERE "id" = 'oc1'`));
  await db.exec(`UPDATE "oauth_client" SET "tinycloudSessionPolicy" = NULL, "tinycloudSessionOrigin" = NULL WHERE "id" = 'oc1'`);

  // Email association and organization custody do not require a passkey. A
  // passkey is an optional account hardening method and a required eject
  // step-up, not an ownership invariant.
  await db.exec(`INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES ('k0', 'u2', '0x0000000000000000000000000000000000000010', '0x10', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', '${contextC}');`);
  await db.exec(`INSERT INTO "managed_account" ("id", "ownerUserId", "organizationId", "subjectEmail", "externalUserId", "keyId", "updatedAt") VALUES ('a0', 'u2', 'o1', 'u2@example.test', 'external-no-passkey', 'k0', '${timestamp}');`);
  await db.exec(`BEGIN; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c0', 'a0', 'ORGANIZATION', 'o1', 1, '${timestamp}'); INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('e0', 'a0', 'k0', 1, 'hash-0', 'none', 'organization:o1', 'INITIAL_ACTIVATION', 'policy', 'signature-0', '${timestamp}'); UPDATE "managed_account" SET "state" = 'MANAGED', "custodyEpoch" = 1, "custodyHeadId" = 'c0' WHERE "id" = 'a0'; COMMIT;`);
  await db.exec(`UPDATE "managed_account" SET "state" = 'DISABLED' WHERE "id" = 'a0'`);
  await db.exec(`UPDATE "managed_account" SET "state" = 'MANAGED' WHERE "id" = 'a0'`);
  const activeWithoutPasskey = await db.query<{ state: string; custodyEpoch: number }>(`SELECT "state", "custodyEpoch" FROM "managed_account" WHERE "id" = 'a0'`);
  expect(activeWithoutPasskey.rows[0]).toEqual({ state: 'MANAGED', custodyEpoch: 1 });

  // The coherent initial transition is the only legal way to create an active head.
  await db.exec(`BEGIN; INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('c1', 'a1', 'ORGANIZATION', 'o1', 1, '${timestamp}'); INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('e1', 'a1', 'k1', 1, 'hash-1', 'none', 'organization:o1', 'INITIAL_ACTIVATION', 'policy', 'signature-1', '${timestamp}'); UPDATE "managed_account" SET "state" = 'MANAGED', "custodyEpoch" = 1, "custodyHeadId" = 'c1' WHERE "id" = 'a1'; COMMIT;`);
  const active = await db.query<{ state: string; custodyEpoch: number }>(`SELECT "state", "custodyEpoch" FROM "managed_account" WHERE "id" = 'a1'`);
  expect(active.rows[0]).toEqual({ state: 'MANAGED', custodyEpoch: 1 });

  // A pre-provisioned managed account can bind owner and key atomically once.
  await db.exec(`INSERT INTO "ethereum_keys" ("id", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES ('k2', '0x0000000000000000000000000000000000000005', '0x5', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', '${contextD}');`);
  await db.exec(`INSERT INTO "managed_account" ("id", "organizationId", "subjectEmail", "keyId", "updatedAt") VALUES ('a2', 'o1', 'u3@example.test', 'k2', '${timestamp}');`);
  await db.exec(`BEGIN; UPDATE "managed_account" SET "ownerUserId" = 'u3' WHERE "id" = 'a2'; UPDATE "ethereum_keys" SET "userId" = 'u3' WHERE "id" = 'k2'; COMMIT;`);
  const bound = await db.query<{ ownerUserId: string | null; userId: string | null }>(`SELECT ma."ownerUserId", ek."userId" FROM "managed_account" ma JOIN "ethereum_keys" ek ON ek."id" = ma."keyId" WHERE ma."id" = 'a2'`);
  expect(bound.rows[0]).toEqual({ ownerUserId: 'u3', userId: 'u3' });
  await expectRejected(() => db.exec(`UPDATE "managed_account" SET "ownerUserId" = NULL WHERE "id" = 'a2'`));
  await expectRejected(() => db.exec(`UPDATE "ethereum_keys" SET "userId" = 'u1' WHERE "id" = 'k2'`));

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
  await db.exec(`UPDATE "managed_account" SET "state" = 'DISABLED' WHERE "id" = 'a1'`);
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
  await db.exec(`INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES ('kq', 'u1', '0x0000000000000000000000000000000000000002', '0x2', 'sealed', 'MANAGED', 'PERSONAL', '${contextB}')`);
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
    await expectRejected(() => upgrade.exec(`UPDATE "ethereum_keys" SET "sealingContext" = '${contextA}' WHERE "id" = 'legacy-null'`));
    await exerciseConstraints(upgrade);
    await upgrade.close();
  });

  test('20260720_0001 backfills subjectEmail from ownerUserId on non-empty databases', async () => {
    // Simulates a production database that has legacy managed_account rows
    // (ownerUserId NOT NULL, no subjectEmail column). The migration must add the
    // column as nullable, backfill from the owner user's email, then enforce NOT NULL.
    const upgrade = new PGlite('memory://');
    // Apply all migrations through the one just before the new migration.
    const preLegacyIdx = migrationNames.indexOf('20260720_0001_tenant_managed_email_accounts');
    await applyMigrations(upgrade, preLegacyIdx);

    // Seed the state that would exist on a production database before the migration:
    // a user, an organization, a plan, a key, and a managed account with ownerUserId.
    // Note: externalUserId is NOT NULL in the pre-migration schema.
    await upgrade.exec(`
      INSERT INTO "user" ("id", "email", "updatedAt") VALUES ('lu1', 'legacy@example.test', '${timestamp}');
      INSERT INTO "organization" ("id", "name", "updatedAt") VALUES ('lo1', 'Legacy Org', '${timestamp}');
      INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext")
        VALUES ('lk1', 'lu1', '0x0000000000000000000000000000000000000011', '0x11', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', '${contextA}');
      INSERT INTO "managed_account" ("id", "ownerUserId", "organizationId", "externalUserId", "keyId", "updatedAt")
        VALUES ('la1', 'lu1', 'lo1', 'ext-lu1', 'lk1', '${timestamp}');
    `);

    // Verify the column does not yet exist
    const before = await upgrade.query<{ exists: boolean }>(`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'managed_account' AND column_name = 'subjectEmail'
      ) AS "exists"
    `);
    expect(before.rows[0]?.exists).toBe(false);

    // Apply the migration – must succeed with the backfill
    await applyMigrationsFrom(upgrade, preLegacyIdx);

    // The legacy row must have been backfilled with the canonical email
    const after = await upgrade.query<{ subjectEmail: string }>(`SELECT "subjectEmail" FROM "managed_account" WHERE "id" = 'la1'`);
    expect(after.rows[0]?.subjectEmail).toBe('legacy@example.test');

    // The unique index must be in place
    const idx = await upgrade.query<{ indexname: string }>(`
      SELECT indexname FROM pg_indexes
      WHERE tablename = 'managed_account' AND indexname = 'managed_account_org_subject_email_key'
    `);
    expect(idx.rows).toHaveLength(1);

    await upgrade.close();
  });

  test('20260720_0001 migrates legacy organization-scoped OAuth clients to TENANT_MANAGED with canonical metadata', async () => {
    // Simulates a production database that has OAuth clients created with organizationId
    // but without the mode column or canonical metadata. The migration must:
    //  1. Add the mode column (DEFAULT PERSONAL)
    //  2. Backfill mode=TENANT_MANAGED for every client that has an organizationId
    //  3. Populate openkeyClientMode AND openkeyOrganizationId in metadata
    const upgrade = new PGlite('memory://');
    const preLegacyIdx = migrationNames.indexOf('20260720_0001_tenant_managed_email_accounts');
    await applyMigrations(upgrade, preLegacyIdx);

    // Insert a legacy organization and two OAuth clients:
    // - lo_tm: bound to the organization (must be migrated to TENANT_MANAGED)
    // - lo_personal: not bound to any organization (must stay PERSONAL)
    await upgrade.exec(`
      INSERT INTO "organization" ("id", "name", "updatedAt") VALUES ('lo_org', 'Legacy Org', '${timestamp}');
      INSERT INTO "oauth_client"
        ("id", "clientId", "name", "redirectUris", "scopes", "organizationId", "contacts", "updatedAt")
        VALUES
          ('lo_tm', 'ok_legacy_tm', 'Tenant App', ARRAY['https://app.example/cb'], ARRAY['openid'], 'lo_org', ARRAY[]::text[], '${timestamp}'),
          ('lo_personal', 'ok_legacy_personal', 'Personal App', ARRAY['https://app.example/cb'], ARRAY['openid'], NULL, ARRAY[]::text[], '${timestamp}');
    `);

    // Verify the mode column does not yet exist
    const before = await upgrade.query<{ exists: boolean }>(`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'oauth_client' AND column_name = 'mode'
      ) AS "exists"
    `);
    expect(before.rows[0]?.exists).toBe(false);

    // Apply the migration
    await applyMigrationsFrom(upgrade, preLegacyIdx);

    // The organization-scoped client must be TENANT_MANAGED with canonical metadata
    const tm = await upgrade.query<{ mode: string; metadata: unknown }>(`
      SELECT "mode", "metadata" FROM "oauth_client" WHERE "id" = 'lo_tm'
    `);
    expect(tm.rows[0]?.mode).toBe('TENANT_MANAGED');
    const tmMeta = tm.rows[0]?.metadata as Record<string, unknown>;
    expect(tmMeta?.openkeyClientMode).toBe('TENANT_MANAGED');
    expect(tmMeta?.openkeyOrganizationId).toBe('lo_org');

    // The non-organization client must remain PERSONAL
    const personal = await upgrade.query<{ mode: string; metadata: unknown }>(`
      SELECT "mode", "metadata" FROM "oauth_client" WHERE "id" = 'lo_personal'
    `);
    expect(personal.rows[0]?.mode).toBe('PERSONAL');

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

// ─── assert-production-migration-ready email predicate checks ───────────────
// These tests exercise the exact SQL from assert-production-migration-ready.ts
// against PGlite to prove each predicate of normalizeSubjectEmail() is enforced:
//   ASCII-only, ≤254 chars, has @, not starts/ends with @.
// They run against the pre-migration schema (before 20260720_0001) to match the
// context in which the preflight script runs in production.

describe('assert-production-migration-ready email predicate checks (PGlite)', () => {
  const preLegacyIdx = migrationNames.indexOf('20260720_0001_tenant_managed_email_accounts');
  const ts = timestamp;

  // Re-uses the sealingContext helper from the outer scope.
  const ctxZ = sealingContext('Z');

  async function setupPreMigrationDb(suffix: string) {
    const db = new PGlite('memory://');
    await applyMigrations(db, preLegacyIdx);
    await db.exec(`
      INSERT INTO "organization" ("id", "name", "updatedAt")
        VALUES ('pmt-org-${suffix}', 'PMT Org', '${ts}');
    `);
    return db;
  }

  // The SQL check extracted verbatim from assert-production-migration-ready.ts
  async function runEmailPredicateCheck(db: PGlite) {
    return db.query<{ id: string; reason: string }>(`
      SELECT
        ma."id",
        CASE
          WHEN octet_length(u."email") > char_length(u."email")
            THEN 'non-ASCII characters'
          WHEN char_length(lower(btrim(u."email", E'\t\n\r\x0c\x0b '))) > 254
            THEN 'exceeds 254 characters after normalization'
          WHEN lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) NOT LIKE '%@%'
            THEN 'missing @ symbol'
          WHEN lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) LIKE '@%'
            THEN 'starts with @'
          WHEN lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) LIKE '%@'
            THEN 'ends with @'
          ELSE 'unknown'
        END AS reason
      FROM "managed_account" ma
      JOIN "user" u ON u.id = ma."ownerUserId"
      WHERE ma."ownerUserId" IS NOT NULL
        AND (
          octet_length(u."email") > char_length(u."email")
          OR char_length(lower(btrim(u."email", E'\t\n\r\x0c\x0b '))) > 254
          OR lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) NOT LIKE '%@%'
          OR lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) LIKE '@%'
          OR lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) LIKE '%@'
        )
    `);
  }

  async function insertLegacyAccountWithEmail(db: PGlite, suffix: string, email: string) {
    await db.exec(`
      INSERT INTO "user" ("id", "email", "updatedAt")
        VALUES ('pmt-u-${suffix}', '${email.replace(/'/g, "''")}', '${ts}');
      INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext")
        VALUES ('pmt-k-${suffix}', 'pmt-u-${suffix}',
          '0x00000000000000000000000000000000DEADDEAD',
          '0xDEAD', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', '${ctxZ}');
      INSERT INTO "managed_account" ("id", "ownerUserId", "organizationId", "externalUserId", "keyId", "updatedAt")
        VALUES ('pmt-a-${suffix}', 'pmt-u-${suffix}', 'pmt-org-${suffix}',
          'ext-${suffix}', 'pmt-k-${suffix}', '${ts}');
    `);
  }

  test('valid ASCII email clears every predicate — check returns no rows', async () => {
    const db = await setupPreMigrationDb('valid');
    await insertLegacyAccountWithEmail(db, 'valid', 'valid@example.test');
    const result = await runEmailPredicateCheck(db);
    expect(result.rows).toHaveLength(0);
    await db.close();
  });

  test('non-ASCII email is flagged', async () => {
    const db = await setupPreMigrationDb('nonascii');
    // Insert directly using PostgreSQL Unicode escape for 'é' (U+00E9, 2 UTF-8 bytes)
    await db.exec(`
      INSERT INTO "organization" ("id", "name", "updatedAt")
        VALUES ('pmt-org-nonascii', 'PMT Org', '${ts}')
        ON CONFLICT DO NOTHING;
    `).catch(() => undefined);
    await db.exec(`
      INSERT INTO "user" ("id", "email", "updatedAt")
        VALUES ('pmt-u-nonascii', U&'\\00E9test@example.test', '${ts}');
      INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext")
        VALUES ('pmt-k-nonascii', 'pmt-u-nonascii',
          '0x00000000000000000000000000000000DEAD0001',
          '0xDE01', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', '${ctxZ}');
      INSERT INTO "managed_account" ("id", "ownerUserId", "organizationId", "externalUserId", "keyId", "updatedAt")
        VALUES ('pmt-a-nonascii', 'pmt-u-nonascii', 'pmt-org-nonascii',
          'ext-nonascii', 'pmt-k-nonascii', '${ts}');
    `);
    const result = await runEmailPredicateCheck(db);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]!.reason).toBe('non-ASCII characters');
    await db.close();
  });

  test('email exceeding 254 characters is flagged', async () => {
    const db = await setupPreMigrationDb('toolong');
    // Build a 255-character email: local part padded so total > 254 chars
    const localPart = 'a'.repeat(245);  // 245 + '@' + 'example.test' (12) = 258 chars total > 254
    const longEmail = `${localPart}@example.test`;
    expect(longEmail.length).toBeGreaterThan(254);
    await insertLegacyAccountWithEmail(db, 'toolong', longEmail);
    const result = await runEmailPredicateCheck(db);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]!.reason).toContain('254 characters');
    await db.close();
  });

  test('email without @ symbol is flagged', async () => {
    const db = await setupPreMigrationDb('noat');
    await insertLegacyAccountWithEmail(db, 'noat', 'no-at-sign.example.test');
    const result = await runEmailPredicateCheck(db);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]!.reason).toBe('missing @ symbol');
    await db.close();
  });

  test('email starting with @ is flagged', async () => {
    const db = await setupPreMigrationDb('startat');
    await insertLegacyAccountWithEmail(db, 'startat', '@starts-with.example.test');
    const result = await runEmailPredicateCheck(db);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]!.reason).toBe('starts with @');
    await db.close();
  });

  test('email ending with @ is flagged', async () => {
    const db = await setupPreMigrationDb('endat');
    await insertLegacyAccountWithEmail(db, 'endat', 'ends-with@');
    const result = await runEmailPredicateCheck(db);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]!.reason).toBe('ends with @');
    await db.close();
  });
});

// ─── listTenantManagedAccounts canonical cursor — PGlite ───────────────────
// These tests verify cursor strictness (rejections) and stable duplicate-free
// multi-page traversal when accounts share the same createdAt timestamp.

describe('listTenantManagedAccounts canonical cursor and stable traversal (PGlite)', () => {
  test('stable duplicate-free multi-page traversal when createdAt values tie', async () => {
    const prisma2 = createPrismaClient({ connectionString: 'pglite://memory://cursor-cursor-validation' });

    // Test 1: Padded (non-minimal) base64url is rejected.
    // Canonical: Buffer.from('{"id":"x","createdAt":"y"}').toString('base64url') = no padding
    // Non-minimal: add trailing '=' padding
    const canonical = Buffer.from('{"id":"x","createdAt":"2026-07-20T12:00:00.000Z"}', 'utf8').toString('base64url');
    expect(canonical).not.toContain('='); // base64url has no padding by definition
    const padded = canonical + '=';
    let threw = false;
    try {
      await listTenantManagedAccounts(prisma2, 'irrelevant', { cursor: padded });
    } catch (e: any) {
      threw = true;
      expect(e.code).toBe('INVALID_REQUEST');
    }
    expect(threw).toBe(true);

    // Test 2: Reordered JSON keys ({"createdAt":"...","id":"..."}) are rejected.
    const reordered = Buffer.from('{"createdAt":"2026-07-20T12:00:00.000Z","id":"x"}', 'utf8').toString('base64url');
    threw = false;
    try {
      await listTenantManagedAccounts(prisma2, 'irrelevant', { cursor: reordered });
    } catch (e: any) {
      threw = true;
      expect(e.code).toBe('INVALID_REQUEST');
    }
    expect(threw).toBe(true);

    // Test 3: Extra JSON keys are rejected.
    const extraKey = Buffer.from('{"id":"x","createdAt":"2026-07-20T12:00:00.000Z","extra":"oops"}', 'utf8').toString('base64url');
    threw = false;
    try {
      await listTenantManagedAccounts(prisma2, 'irrelevant', { cursor: extraKey });
    } catch (e: any) {
      threw = true;
      expect(e.code).toBe('INVALID_REQUEST');
    }
    expect(threw).toBe(true);

    // Test 4: JSON whitespace is rejected.
    const withSpace = Buffer.from('{"id": "x","createdAt":"2026-07-20T12:00:00.000Z"}', 'utf8').toString('base64url');
    threw = false;
    try {
      await listTenantManagedAccounts(prisma2, 'irrelevant', { cursor: withSpace });
    } catch (e: any) {
      threw = true;
      expect(e.code).toBe('INVALID_REQUEST');
    }
    expect(threw).toBe(true);

    // Test 5: Noncanonical timestamp (date-only format) is rejected.
    const dateOnly = Buffer.from('{"id":"x","createdAt":"2026-07-20"}', 'utf8').toString('base64url');
    threw = false;
    try {
      await listTenantManagedAccounts(prisma2, 'irrelevant', { cursor: dateOnly });
    } catch (e: any) {
      threw = true;
      expect(e.code).toBe('INVALID_REQUEST');
    }
    expect(threw).toBe(true);

    // Test 6: Invalid calendar date is rejected (passes regex but NaN Date).
    const badDate = Buffer.from('{"id":"x","createdAt":"2026-13-40T00:00:00.000Z"}', 'utf8').toString('base64url');
    threw = false;
    try {
      await listTenantManagedAccounts(prisma2, 'irrelevant', { cursor: badDate });
    } catch (e: any) {
      threw = true;
      expect(e.code).toBe('INVALID_REQUEST');
    }
    expect(threw).toBe(true);

    // Test 7: Empty id is rejected.
    const emptyId = Buffer.from('{"id":"","createdAt":"2026-07-20T12:00:00.000Z"}', 'utf8').toString('base64url');
    threw = false;
    try {
      await listTenantManagedAccounts(prisma2, 'irrelevant', { cursor: emptyId });
    } catch (e: any) {
      threw = true;
      expect(e.code).toBe('INVALID_REQUEST');
    }
    expect(threw).toBe(true);

    // Test 8: Whitespace-only id is rejected.
    const wsId = Buffer.from('{"id":"   ","createdAt":"2026-07-20T12:00:00.000Z"}', 'utf8').toString('base64url');
    threw = false;
    try {
      await listTenantManagedAccounts(prisma2, 'irrelevant', { cursor: wsId });
    } catch (e: any) {
      threw = true;
      expect(e.code).toBe('INVALID_REQUEST');
    }
    expect(threw).toBe(true);

    await prisma2.$disconnect();
  });

  test('stable duplicate-free traversal collects all accounts with tied createdAt', async () => {
    const tdb = new PGlite('memory://');
    await applyMigrations(tdb);
    const prisma = new PrismaClient({ adapter: new PrismaPGlite(tdb) });
    const orgId = 'trav-org';
    const tiedAt = new Date('2026-07-20T12:00:00.000Z');
    try {
      await tdb.exec(`
        INSERT INTO "organization" ("id", "name", "updatedAt") VALUES ('${orgId}', 'Trav Org', '${timestamp}');
        INSERT INTO "plan_entitlements" ("id", "organizationId", "maxApps", "maxOrganizationMembers", "maxManagedAccounts", "monthlyActiveManagedUsers", "storageBytesPerManagedAccount", "requestsPerMinute", "maxTenantDelegationTtlSeconds", "maxTenantPolicyVersion", "auditRetentionDays", "updatedAt")
          VALUES ('trav-ent', '${orgId}', 3, 3, 100, 100, 1000, 60, 3600, 1, 30, '${timestamp}');
      `);

      for (let i = 5; i >= 1; i--) {
        const id = `trav-acct-${i.toString().padStart(2, '0')}`;
        const addr = `0x${(0x100 + i).toString(16).padStart(40, '0')}`;
        const ctx = sealingContext(`T${i}`);
        await tdb.exec(`
          INSERT INTO "ethereum_keys" ("id", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext")
            VALUES ('trav-k-${i}', '${addr}', '${addr}', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', '${ctx}');
          INSERT INTO "managed_account" ("id", "organizationId", "subjectEmail", "keyId", "state", "custodyEpoch", "updatedAt", "createdAt")
            VALUES ('${id}', '${orgId}', 'trav${i}@example.test', 'trav-k-${i}', 'PROVISIONED', 0, '${tiedAt.toISOString()}', '${tiedAt.toISOString()}');
          INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt")
            VALUES ('trav-custody-${i}', '${id}', 'ORGANIZATION', '${orgId}', 1, '${tiedAt.toISOString()}');
          INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt")
            VALUES ('trav-event-${i}', '${id}', 'trav-k-${i}', 1, 'trav-hash-${i}', 'none', 'organization:${orgId}', 'INITIAL_ACTIVATION', 'policy', 'signature-${i}', '${tiedAt.toISOString()}');
          UPDATE "managed_account" SET "state" = 'MANAGED', "custodyEpoch" = 1, "custodyHeadId" = 'trav-custody-${i}' WHERE "id" = '${id}';
        `);
      }

      const page1 = await listTenantManagedAccounts(prisma, orgId, { limit: 2 });
      expect(page1.accounts.map((account) => account.id)).toEqual(['trav-acct-05', 'trav-acct-04']);
      expect(page1.nextCursor).toBeTruthy();
      const page2 = await listTenantManagedAccounts(prisma, orgId, { limit: 2, cursor: page1.nextCursor! });
      expect(page2.accounts.map((account) => account.id)).toEqual(['trav-acct-03', 'trav-acct-02']);
      const page3 = await listTenantManagedAccounts(prisma, orgId, { limit: 2, cursor: page2.nextCursor! });
      expect(page3.accounts.map((account) => account.id)).toEqual(['trav-acct-01']);
      expect(page3.nextCursor).toBeNull();
      expect(new Set([...page1.accounts, ...page2.accounts, ...page3.accounts].map((account) => account.id)).size).toBe(5);
    } finally {
      await prisma.$disconnect();
      await tdb.close();
    }
  });
});

// ─── Real PostgreSQL: createTenantManagedAccount production code tests ───────
// These tests call the actual production createTenantManagedAccount function
// against a real PostgreSQL database to prove idempotency and quota enforcement
// through production code, not raw-SQL simulation.

test.skipIf(!externalUrl)(
  'createTenantManagedAccount concurrent same-key calls are idempotent (production code, real PostgreSQL)',
  async () => {
    const schema = `openkey_prod_idem_${randomUUID().replaceAll('-', '')}`;
    const setupClient = new Client({ connectionString: externalUrl });
    await setupClient.connect();
    try {
      await setupClient.query(`CREATE SCHEMA "${schema}"`);
      await setupClient.query(`SET search_path TO "${schema}"`);

      const db: SqlExecutor = {
        exec: async (sql) => { await setupClient.query(sql); },
        query: async <T>(sql: string) => setupClient.query(sql) as unknown as Promise<{ rows: T[] }>,
      };
      await applyMigrations(db);

      const ts = timestamp;
      const orgId = 'pi-org';
      await db.exec(`
        INSERT INTO "user" ("id", "email", "updatedAt")
          VALUES ('pi-user', 'pi-user@example.test', '${ts}');
        INSERT INTO "organization" ("id", "name", "updatedAt")
          VALUES ('${orgId}', 'Prod Idem Org', '${ts}');
        INSERT INTO "organization_membership"
          ("id", "organizationId", "userId", "role", "status", "validFrom")
          VALUES ('pi-membership', '${orgId}', 'pi-user', 'ADMIN', 'ACTIVE', '${ts}');
        INSERT INTO "plan_entitlements" ("id", "organizationId", "maxApps", "maxOrganizationMembers", "maxManagedAccounts", "monthlyActiveManagedUsers", "storageBytesPerManagedAccount", "requestsPerMinute", "maxTenantDelegationTtlSeconds", "maxTenantPolicyVersion", "auditRetentionDays", "updatedAt")
          VALUES ('pi-ent', '${orgId}', 3, 3, 10, 100, 1000, 60, 3600, 1, 30, '${ts}');
      `);

      // Build a Prisma client whose connections use the isolated schema.
      // The ?options=-csearch_path=X startup parameter is parsed by pg-connection-string
      // and sets search_path for every connection the pool establishes.
      const prisma = createPrismaClient({ connectionString: externalUrl!, schema });
      const tee = createTeeClient();
      const now = new Date();
      const issued = await issueOrganizationCredential(prisma, {
        organizationId: orgId,
        subjectUserId: 'pi-user',
        name: 'Prod Idem Cred',
      }, now);
      const authenticated = await authenticateOrganizationCredential(prisma, issued.secret, now);
      if (authenticated.kind !== 'MANAGEMENT') throw new Error('Expected a MANAGEMENT credential');
      const actor = authenticated as ManagementActor;

      try {
        // Two concurrent calls with the same idempotency key and email must
        // produce exactly one account and return the same ID to both callers.
        const [r1, r2] = await Promise.all([
          createTenantManagedAccount(
            prisma, { credential: actor, idempotencyKey: 'prod-idem-key-1', email: 'concurrent@example.test' },
            tee, now,
          ),
          createTenantManagedAccount(
            prisma, { credential: actor, idempotencyKey: 'prod-idem-key-1', email: 'concurrent@example.test' },
            tee, now,
          ),
        ]);

        // Both callers receive the same account
        expect(r1.id).toBe(r2.id);
        expect(r1.subjectEmail).toBe('concurrent@example.test');
        expect(r2.subjectEmail).toBe('concurrent@example.test');

        const listed = await listTenantManagedAccounts(prisma, orgId, { limit: 10 });
        expect(listed.accounts).toHaveLength(1);
        expect(listed.accounts[0]?.id).toBe(r1.id);

        // Exactly one call was a true create; the other received the replay
        const createdCount = [r1.created, r2.created].filter(Boolean).length;
        expect(createdCount).toBe(1);

        // Both results carry the state that production code would return
        expect(r1.state).toBe('MANAGED');
        expect(r2.state).toBe('MANAGED');
      } finally {
        await prisma.$disconnect();
      }
    } finally {
      await setupClient.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
      await setupClient.end();
    }
  },
  60_000,
);

test.skipIf(!externalUrl)(
  'createTenantManagedAccount enforces quota through production code (real PostgreSQL)',
  async () => {
    const schema = `openkey_prod_quota_${randomUUID().replaceAll('-', '')}`;
    const setupClient = new Client({ connectionString: externalUrl });
    await setupClient.connect();
    try {
      await setupClient.query(`CREATE SCHEMA "${schema}"`);
      await setupClient.query(`SET search_path TO "${schema}"`);

      const db: SqlExecutor = {
        exec: async (sql) => { await setupClient.query(sql); },
        query: async <T>(sql: string) => setupClient.query(sql) as unknown as Promise<{ rows: T[] }>,
      };
      await applyMigrations(db);

      const ts = timestamp;
      const orgId = 'pq-org';
      await db.exec(`
        INSERT INTO "user" ("id", "email", "updatedAt")
          VALUES ('pq-user', 'pq-user@example.test', '${ts}');
        INSERT INTO "organization" ("id", "name", "updatedAt")
          VALUES ('${orgId}', 'Prod Quota Org', '${ts}');
        INSERT INTO "organization_membership"
          ("id", "organizationId", "userId", "role", "status", "validFrom")
          VALUES ('pq-membership', '${orgId}', 'pq-user', 'ADMIN', 'ACTIVE', '${ts}');
        INSERT INTO "plan_entitlements" ("id", "organizationId", "maxApps", "maxOrganizationMembers", "maxManagedAccounts", "monthlyActiveManagedUsers", "storageBytesPerManagedAccount", "requestsPerMinute", "maxTenantDelegationTtlSeconds", "maxTenantPolicyVersion", "auditRetentionDays", "updatedAt")
          VALUES ('pq-ent', '${orgId}', 3, 3, 1, 100, 1000, 60, 3600, 1, 30, '${ts}');
      `);

      const prisma = createPrismaClient({ connectionString: externalUrl!, schema });
      const tee = createTeeClient();
      const now = new Date();
      const issued = await issueOrganizationCredential(prisma, {
        organizationId: orgId,
        subjectUserId: 'pq-user',
        name: 'Prod Quota Cred',
      }, now);
      const authenticated = await authenticateOrganizationCredential(prisma, issued.secret, now);
      if (authenticated.kind !== 'MANAGEMENT') throw new Error('Expected a MANAGEMENT credential');
      const actor = authenticated as ManagementActor;

      try {
        const results = await Promise.allSettled([
          createTenantManagedAccount(
            prisma, { credential: actor, idempotencyKey: 'pq-key-1', email: 'first@example.test' },
            tee, now,
          ),
          createTenantManagedAccount(
            prisma, { credential: actor, idempotencyKey: 'pq-key-2', email: 'second@example.test' },
            tee, now,
          ),
        ]);
        const fulfilled = results.filter((result): result is PromiseFulfilledResult<any> => result.status === 'fulfilled');
        const rejected = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
        expect(fulfilled).toHaveLength(1);
        expect(fulfilled[0]!.value.created).toBe(true);
        expect(rejected).toHaveLength(1);
        expect(rejected[0]!.reason.code).toBe('OPERATION_NOT_ALLOWED');

        const listed = await listTenantManagedAccounts(prisma, orgId, { limit: 10 });
        expect(listed.accounts).toHaveLength(1);
        expect(listed.accounts[0]?.subjectEmail).toBe(fulfilled[0]!.value.subjectEmail);
      } finally {
        await prisma.$disconnect();
      }
    } finally {
      await setupClient.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
      await setupClient.end();
    }
  },
  60_000,
);
