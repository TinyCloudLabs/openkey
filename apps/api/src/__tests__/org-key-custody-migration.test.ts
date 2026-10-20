import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// Applies every tracked migration, in order, to a real Postgres engine (PGlite)
// and exercises the TC-1518 constraints directly.
const root = resolve(import.meta.dir, '../../../..');
let directory: string;
let database: PGlite;
let sequence = 0;

// Sealing contexts are 43 base64url characters (services/key-sealing.ts).
function sealingContext(n: number): string {
  return `${String(n).padStart(42, '0')}A`;
}

function nextSequence(): number {
  sequence += 1;
  return sequence;
}

async function insertKey(options: {
  custody?: 'PERSONAL' | 'ORG';
  userId?: string | null;
  sealingContext?: string | null;
  canonical?: boolean;
} = {}): Promise<string> {
  const n = nextSequence();
  const id = `key-${n}`;
  await database.query(
    `INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealingContext", "keyType", "custody", "isCanonicalTinyCloud")
     VALUES ($1, $2, $3, 'pk', $4, 'MANAGED', $5, $6)`,
    [
      id,
      options.userId ?? null,
      `0x${n.toString(16).padStart(40, '0')}`,
      options.sealingContext ?? null,
      options.custody ?? 'PERSONAL',
      options.canonical ?? false,
    ],
  );
  return id;
}

async function insertOrgKey(): Promise<string> {
  const keyId = await insertKey({ custody: 'ORG', sealingContext: sealingContext(nextSequence()) });
  await database.query(
    `INSERT INTO "org_keys" ("keyId", "orgId", "orgName", "controllerDid") VALUES ($1, 'org-1', 'Org One', 'did:pkh:eip155:1:0x0')`,
    [keyId],
  );
  return keyId;
}

async function insertGrant(keyId: string, role: 'OWNER' | 'ADMIN', userId: string, revokedAt: string | null = null): Promise<string> {
  const id = `grant-${nextSequence()}`;
  await database.query(
    `INSERT INTO "key_grants" ("id", "keyId", "role", "granteeUserId", "revokedAt") VALUES ($1, $2, $3, $4, $5)`,
    [id, keyId, role, userId, revokedAt],
  );
  return id;
}

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'openkey-org-key-custody-'));
  database = new PGlite(directory);
  const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  for (const migration of migrations) {
    await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
  }
  await database.exec(`
    INSERT INTO "user" ("id", "email", "updatedAt") VALUES
      ('owner-a', 'owner-a@example.test', now()),
      ('owner-b', 'owner-b@example.test', now());
  `);
});

afterAll(async () => {
  await database.close();
  await rm(directory, { recursive: true, force: true });
});

describe('ORG key custody shape (TC-1518 D1)', () => {
  test('personal keys default to PERSONAL custody', async () => {
    const keyId = await insertKey({ userId: 'owner-a' });
    const rows = await database.query<{ custody: string }>(
      `SELECT "custody" FROM "ethereum_keys" WHERE "id" = $1`,
      [keyId],
    );
    expect(rows.rows[0]?.custody).toBe('PERSONAL');
  });

  test('an ORG key with a personal owner is rejected', async () => {
    await expect(insertKey({ custody: 'ORG', userId: 'owner-a', sealingContext: sealingContext(9001) }))
      .rejects.toThrow(/ethereum_keys_custody_org_shape_check/);
  });

  test('an ORG key without a per-key seal is rejected', async () => {
    await expect(insertKey({ custody: 'ORG', sealingContext: null }))
      .rejects.toThrow(/ethereum_keys_custody_org_shape_check/);
  });

  test('an ORG key marked as canonical TinyCloud is rejected', async () => {
    await expect(insertKey({ custody: 'ORG', sealingContext: sealingContext(9002), canonical: true }))
      .rejects.toThrow(/ethereum_keys_custody_org_shape_check/);
  });

  test('a well-formed ORG key is accepted', async () => {
    const keyId = await insertOrgKey();
    const rows = await database.query<{ custody: string; userId: string | null }>(
      `SELECT "custody", "userId" FROM "ethereum_keys" WHERE "id" = $1`,
      [keyId],
    );
    expect(rows.rows[0]).toEqual({ custody: 'ORG', userId: null });
  });
});

describe('org key grants (TC-1518 D2)', () => {
  test('a second active OWNER grant on one key is rejected', async () => {
    const keyId = await insertOrgKey();
    await insertGrant(keyId, 'OWNER', 'owner-a');
    await expect(insertGrant(keyId, 'OWNER', 'owner-b')).rejects.toThrow(/key_grants_one_active_owner_per_key/);
  });

  test('a revoked OWNER grant does not block a new active OWNER', async () => {
    const keyId = await insertOrgKey();
    await insertGrant(keyId, 'OWNER', 'owner-a', '2026-10-21T00:00:00Z');
    await insertGrant(keyId, 'OWNER', 'owner-b');
    const rows = await database.query<{ count: string }>(
      `SELECT count(*)::text AS "count" FROM "key_grants" WHERE "keyId" = $1 AND "revokedAt" IS NULL`,
      [keyId],
    );
    expect(rows.rows[0]?.count).toBe('1');
  });

  test('the OWNER uniqueness rule does not limit ADMIN grants', async () => {
    const keyId = await insertOrgKey();
    await insertGrant(keyId, 'OWNER', 'owner-a');
    await insertGrant(keyId, 'ADMIN', 'owner-b');
    await insertGrant(keyId, 'ADMIN', 'owner-b');
    const rows = await database.query<{ count: string }>(
      `SELECT count(*)::text AS "count" FROM "key_grants" WHERE "keyId" = $1`,
      [keyId],
    );
    expect(rows.rows[0]?.count).toBe('3');
  });

  test('an ORG key with an org record cannot be deleted while it is referenced', async () => {
    const keyId = await insertOrgKey();
    await expect(database.query(`DELETE FROM "ethereum_keys" WHERE "id" = $1`, [keyId]))
      .rejects.toThrow(/org_keys_keyId_fkey|key_grants_keyId_fkey/);
  });
});

describe('org key signing challenges and audit columns (TC-1518 K2a)', () => {
  async function insertChallenge(options: { nonce: string; keyId: string; grantId: string; userId?: string }) {
    await database.query(
      `INSERT INTO "org_key_sign_challenges" ("id", "userId", "keyId", "grantId", "nonce", "messageDigest", "expiresAt")
       VALUES ($1, $2, $3, $4, $5, 'digest', now() + interval '5 minutes')`,
      [`challenge-${nextSequence()}`, options.userId ?? 'owner-a', options.keyId, options.grantId, options.nonce],
    );
  }

  test('a challenge nonce is unique across all challenges', async () => {
    const keyId = await insertOrgKey();
    const grantId = await insertGrant(keyId, 'OWNER', 'owner-a');
    await insertChallenge({ nonce: 'nonce-unique-1', keyId, grantId });
    await expect(insertChallenge({ nonce: 'nonce-unique-1', keyId, grantId }))
      .rejects.toThrow(/org_key_sign_challenges_nonce_key/);
  });

  test('a challenge must reference an existing key and grant', async () => {
    const keyId = await insertOrgKey();
    const grantId = await insertGrant(keyId, 'OWNER', 'owner-a');
    await expect(insertChallenge({ nonce: 'nonce-fk-1', keyId: 'no-such-key', grantId }))
      .rejects.toThrow(/org_key_sign_challenges_keyId_fkey/);
    await expect(insertChallenge({ nonce: 'nonce-fk-2', keyId, grantId: 'no-such-grant' }))
      .rejects.toThrow(/org_key_sign_challenges_grantId_fkey/);
  });

  test('deleting a user removes that user\'s challenges', async () => {
    await database.exec(`INSERT INTO "user" ("id", "email", "updatedAt") VALUES ('owner-c', 'owner-c@example.test', now())`);
    const keyId = await insertOrgKey();
    const grantId = await insertGrant(keyId, 'OWNER', 'owner-a');
    await insertChallenge({ nonce: 'nonce-cascade-1', keyId, grantId, userId: 'owner-c' });
    await database.query(`DELETE FROM "user" WHERE "id" = 'owner-c'`);
    const rows = await database.query<{ count: string }>(
      `SELECT count(*)::text AS "count" FROM "org_key_sign_challenges" WHERE "nonce" = 'nonce-cascade-1'`,
    );
    expect(rows.rows[0]?.count).toBe('0');
  });

  test('an audit row without a grant role is rejected', async () => {
    const keyId = await insertOrgKey();
    const grantId = await insertGrant(keyId, 'OWNER', 'owner-a');
    await expect(database.query(
      `INSERT INTO "org_key_signature_audits" ("id", "keyId", "grantId", "actorUserId", "origin", "messageDigest", "passkeyAssertionHash", "messageKind")
       VALUES ('audit-no-role', $1, $2, 'owner-a', 'https://openkey.test', 'digest', 'hash-no-role', 'k4.kind')`,
      [keyId, grantId],
    )).rejects.toThrow(/null value in column "role"/);
  });

  test('an audit row without a message kind is rejected', async () => {
    const keyId = await insertOrgKey();
    const grantId = await insertGrant(keyId, 'OWNER', 'owner-a');
    await expect(database.query(
      `INSERT INTO "org_key_signature_audits" ("id", "keyId", "grantId", "actorUserId", "origin", "messageDigest", "passkeyAssertionHash", "role")
       VALUES ('audit-no-kind', $1, $2, 'owner-a', 'https://openkey.test', 'digest', 'hash-no-kind', 'OWNER')`,
      [keyId, grantId],
    )).rejects.toThrow(/null value in column "messageKind"/);
  });

  test('an audit row with a grant role and message kind is accepted', async () => {
    const keyId = await insertOrgKey();
    const grantId = await insertGrant(keyId, 'OWNER', 'owner-a');
    await database.query(
      `INSERT INTO "org_key_signature_audits" ("id", "keyId", "grantId", "actorUserId", "origin", "messageDigest", "passkeyAssertionHash", "role", "messageKind")
       VALUES ('audit-ok', $1, $2, 'owner-a', 'https://openkey.test', 'digest', 'hash-ok', 'OWNER', 'k4.kind')`,
      [keyId, grantId],
    );
    const rows = await database.query<{ role: string; messageKind: string }>(
      `SELECT "role", "messageKind" FROM "org_key_signature_audits" WHERE "id" = 'audit-ok'`,
    );
    expect(rows.rows[0]).toEqual({ role: 'OWNER', messageKind: 'k4.kind' });
  });
});
