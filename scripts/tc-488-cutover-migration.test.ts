import { afterAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const cutover = '20260806_0002_remove_organization_key_custody';
const directory = await mkdtemp(join(tmpdir(), 'openkey-tc-488-cutover-'));
const database = new PGlite(directory);
const migrations = (await readdir('packages/db/prisma/migrations', { withFileTypes: true }))
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

for (const migration of migrations.filter((name) => name !== cutover)) {
  await database.exec(await readFile(`packages/db/prisma/migrations/${migration}/migration.sql`, 'utf8'));
}

await database.exec(`
  INSERT INTO "user" ("id", "email", "emailVerified", "updatedAt")
    VALUES ('member', 'member@example.test', true, CURRENT_TIMESTAMP);
  INSERT INTO "organization" ("id", "name", "updatedAt")
    VALUES ('developer-org', 'Developer organization', CURRENT_TIMESTAMP);
  INSERT INTO "organization_membership" ("id", "organizationId", "userId", "role")
    VALUES ('membership', 'developer-org', 'member', 'ADMIN');
  INSERT INTO "oauth_client" (
    "id", "clientId", "clientSecret", "mode", "name", "redirectUris", "scopes",
    "organizationId", "metadata", "updatedAt"
  ) VALUES (
    'app', 'existing-app', 'hashed-secret', 'TENANT_MANAGED', 'Existing app',
    ARRAY['https://app.example/callback'], ARRAY['openid', 'email', 'tinycloud:manage-key'],
    'developer-org', '{"openkeyClientMode":"TENANT_MANAGED","openkeyOrganizationId":"developer-org","retained":"yes"}'::jsonb,
    CURRENT_TIMESTAMP
  );
  INSERT INTO "oauth_consent" ("id", "userId", "clientId", "scopes", "updatedAt")
    VALUES ('consent', 'member', 'existing-app', ARRAY['openid', 'tinycloud:manage-key'], CURRENT_TIMESTAMP);
  INSERT INTO "ethereum_keys" (
    "id", "userId", "address", "publicKey", "sealedBlob", "sealingContext", "keyPurpose"
  ) VALUES (
    'tenant-key', 'member', '0x1111111111111111111111111111111111111111', '0x1', 'sealed',
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'MANAGED_ACCOUNT'
  );
`);

await database.exec(await readFile(`packages/db/prisma/migrations/${cutover}/migration.sql`, 'utf8'));

afterAll(async () => {
  await database.close();
  await rm(directory, { recursive: true, force: true });
});

describe('TC-488 cutover migration', () => {
  test('preserves OAuth configuration and consent while deleting tenant custody state', async () => {
    const clients = await database.query<{
      clientSecret: string;
      redirectUris: string[];
      scopes: string[];
      organizationId: string;
      metadata: { retained: string; openkeyClientMode?: string; openkeyOrganizationId?: string };
    }>(`SELECT "clientSecret", "redirectUris", "scopes", "organizationId", "metadata" FROM "oauth_client" WHERE "clientId" = 'existing-app'`);
    expect(clients.rows).toEqual([{
      clientSecret: 'hashed-secret',
      redirectUris: ['https://app.example/callback'],
      scopes: ['openid', 'email', 'tinycloud:manage-key'],
      organizationId: 'developer-org',
      metadata: { retained: 'yes' },
    }]);
    expect((await database.query(`SELECT "userId", "clientId", "scopes" FROM "oauth_consent"`)).rows).toEqual([{
      userId: 'member', clientId: 'existing-app', scopes: ['openid', 'tinycloud:manage-key'],
    }]);

    await database.exec(`
      UPDATE "organization_membership"
      SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP, "validUntil" = CURRENT_TIMESTAMP
      WHERE "id" = 'membership'
    `);
    expect((await database.query(`SELECT "organizationId" FROM "oauth_client" WHERE "clientId" = 'existing-app'`)).rows)
      .toEqual([{ organizationId: 'developer-org' }]);
    expect((await database.query(`SELECT COUNT(*)::int AS count FROM "ethereum_keys" WHERE "id" = 'tenant-key'`)).rows)
      .toEqual([{ count: 0 }]);
    expect((await database.query(`SELECT to_regclass('public.managed_account') AS relation`)).rows)
      .toEqual([{ relation: null }]);
    expect((await database.query(`SELECT 1 FROM information_schema.columns WHERE table_name = 'ethereum_keys' AND column_name = 'keyPurpose'`)).rows)
      .toEqual([]);
  });

  test('retains database enforcement of one active canonical key per user', async () => {
    expect((await database.query(`
      SELECT i.indisunique AS unique
      FROM pg_class index_class
      JOIN pg_namespace namespace ON namespace.oid = index_class.relnamespace
      JOIN pg_index i ON i.indexrelid = index_class.oid
      WHERE namespace.nspname = 'public'
        AND index_class.relname = 'ethereum_keys_one_active_canonical_tinycloud_key'
    `)).rows).toEqual([{ unique: true }]);

    await database.exec(`
      INSERT INTO "user" ("id", "email", "emailVerified", "updatedAt")
        VALUES ('canonical-member', 'canonical@example.test', true, CURRENT_TIMESTAMP);
      INSERT INTO "ethereum_keys" (
        "id", "userId", "address", "publicKey", "sealedBlob", "sealingContext", "isCanonicalTinyCloud"
      ) VALUES (
        'canonical-key-a', 'canonical-member', '0x2222222222222222222222222222222222222222',
        '0x2', 'sealed-a', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', true
      );
    `);

    await expect(database.exec(`
      INSERT INTO "ethereum_keys" (
        "id", "userId", "address", "publicKey", "sealedBlob", "sealingContext", "isCanonicalTinyCloud"
      ) VALUES (
        'canonical-key-b', 'canonical-member', '0x3333333333333333333333333333333333333333',
        '0x3', 'sealed-b', 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE', true
      );
    `)).rejects.toThrow(/ethereum_keys_one_active_canonical_tinycloud_key/u);
  });
});
