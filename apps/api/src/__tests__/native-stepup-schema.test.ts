import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';

import { assertNativeDelegationSchema } from '../../../../scripts/native-delegation-schema-guards';

// TC-3569: the step-up table, run on the real tracked migration chain. A
// step-up must never outlive its grant, whichever path revokes or deletes it.
const root = resolve(import.meta.dir, '../../../..');
let directory: string;
let db: PGlite;

async function seedGrant(id: string) {
  await db.exec(`
    INSERT INTO "user" ("id", "email", "emailVerified", "name", "updatedAt")
      VALUES ('u-${id}', '${id}@example.test', true, 'Owner', CURRENT_TIMESTAMP);
    INSERT INTO "oauth_client" (
      "id", "clientId", "name", "redirectUris", "scopes", "disabled", "skipConsent", "enableEndSession",
      "tokenEndpointAuthMethod", "grantTypes", "responseTypes", "type", "public", "contacts", "updatedAt"
    ) VALUES (
      'c-${id}', 'client-${id}', 'Home', ARRAY['xyz.tinycloud.exo://openkey/callback'], ARRAY['openid'], false, false, false,
      'none', ARRAY['authorization_code'], ARRAY['code'], 'native', true, ARRAY[]::TEXT[], CURRENT_TIMESTAMP
    );
    INSERT INTO "tinycloud_native_grant" (
      "id", "userId", "clientId", "consentId", "consentGeneration", "keyId", "address", "sessionDid", "sessionJwk",
      "sessionJkt", "spaceId", "approvedPermissions", "ttlSeconds", "tinycloudHost", "absoluteExpiresAt"
    ) VALUES (
      'g-${id}', 'u-${id}', 'client-${id}', 'consent', 0, 'key', '0x0', 'did:key:z6Mk', '{}'::JSONB,
      'jkt', 'space', '[]'::JSONB, 3600, 'https://tee.node.tinycloud.xyz', CURRENT_TIMESTAMP + interval '1 day'
    );
  `);
}

async function addStepUp(grant: string, app: string) {
  await db.query(
    `INSERT INTO "tinycloud_native_stepup" ("id", "grantId", "appId", "approvedPermissions") VALUES ($1, $2, $3, '[]'::JSONB)`,
    [`s-${grant}-${app}`, grant, app],
  );
}

async function statuses(grant: string) {
  const rows = await db.query<{ appId: string; status: string; revokedReason: string | null; revoked: boolean }>(
    `SELECT "appId", "status", "revokedReason", "revokedAt" IS NOT NULL AS revoked FROM "tinycloud_native_stepup" WHERE "grantId" = $1 ORDER BY "appId"`,
    [grant],
  );
  return rows.rows;
}

describe('tinycloud_native_stepup', () => {
  beforeAll(async () => {
    directory = await mkdtemp('/var/tmp/tc3569-db.');
    db = new PGlite(directory);
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) {
      await db.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
  });

  afterAll(async () => {
    await db.close();
    await rm(directory, { recursive: true, force: true });
  });

  test('the physical schema guard accepts the migrated schema', async () => {
    await expect(assertNativeDelegationSchema({
      $queryRawUnsafe: async <T>(query: string, ...values: unknown[]) => (await db.query(query, values)).rows as T,
    })).resolves.toBeUndefined();
  });

  test('revoking a grant revokes all of its step-ups and no other grant\'s', async () => {
    await seedGrant('a');
    await seedGrant('b');
    for (const app of ['explorer', 'account']) await addStepUp('g-a', app);
    await addStepUp('g-b', 'explorer');

    await db.exec(`UPDATE "tinycloud_native_grant" SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP, "revokedReason" = 'client_signout' WHERE "id" = 'g-a'`);

    expect(await statuses('g-a')).toEqual([
      { appId: 'account', status: 'REVOKED', revokedReason: 'grant_revoked', revoked: true },
      { appId: 'explorer', status: 'REVOKED', revokedReason: 'grant_revoked', revoked: true },
    ]);
    expect(await statuses('g-b')).toEqual([{ appId: 'explorer', status: 'ACTIVE', revokedReason: null, revoked: false }]);
  });

  test('a step-up revoked on its own keeps its reason when the grant is revoked later', async () => {
    await seedGrant('c');
    await addStepUp('g-c', 'explorer');
    await addStepUp('g-c', 'courier');
    await db.exec(`UPDATE "tinycloud_native_stepup" SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP, "revokedReason" = 'app_revoked' WHERE "id" = 's-g-c-explorer'`);

    await db.exec(`UPDATE "tinycloud_native_grant" SET "status" = 'REVOKED' WHERE "id" = 'g-c'`);

    expect(await statuses('g-c')).toEqual([
      { appId: 'courier', status: 'REVOKED', revokedReason: 'grant_revoked', revoked: true },
      { appId: 'explorer', status: 'REVOKED', revokedReason: 'app_revoked', revoked: true },
    ]);
  });

  test('consent withdrawal, which revokes grants in SQL, takes the step-ups with it', async () => {
    await seedGrant('d');
    await addStepUp('g-d', 'explorer');
    await db.exec(`
      INSERT INTO "oauth_consent" ("id", "clientId", "userId", "scopes", "createdAt", "updatedAt")
        VALUES ('consent-d', 'client-d', 'u-d', ARRAY['openid', 'tinycloud:delegation'], CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
      DELETE FROM "oauth_consent" WHERE "id" = 'consent-d';
    `);

    expect((await db.query<{ status: string }>(`SELECT "status" FROM "tinycloud_native_grant" WHERE "id" = 'g-d'`)).rows[0]?.status).toBe('REVOKED');
    expect(await statuses('g-d')).toEqual([{ appId: 'explorer', status: 'REVOKED', revokedReason: 'grant_revoked', revoked: true }]);
  });

  test('an ACTIVE step-up cannot be inserted on a grant that is not ACTIVE', async () => {
    await seedGrant('f');
    await db.exec(`UPDATE "tinycloud_native_grant" SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP, "revokedReason" = 'client_signout' WHERE "id" = 'g-f'`);

    await expect(addStepUp('g-f', 'explorer')).rejects.toMatchObject({ code: 'TC773' });
    expect(await statuses('g-f')).toEqual([]);
    // A grant that does not exist is refused too, before the foreign key is reached.
    await expect(addStepUp('g-missing', 'explorer')).rejects.toMatchObject({ code: 'TC773' });
  });

  test('a step-up taken down with its grant never becomes ACTIVE again', async () => {
    await seedGrant('g');
    await addStepUp('g-g', 'explorer');
    await db.exec(`UPDATE "tinycloud_native_grant" SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP WHERE "id" = 'g-g'`);

    await expect(db.exec(`UPDATE "tinycloud_native_stepup" SET "status" = 'ACTIVE' WHERE "grantId" = 'g-g'`)).rejects.toMatchObject({ code: 'TC773' });
    // Even if the grant row were ACTIVE again, the reason keeps the step-up down.
    await db.exec(`UPDATE "tinycloud_native_grant" SET "status" = 'ACTIVE', "revokedAt" = NULL WHERE "id" = 'g-g'`);
    await expect(db.exec(`UPDATE "tinycloud_native_stepup" SET "status" = 'ACTIVE', "revokedReason" = NULL WHERE "grantId" = 'g-g'`)).rejects.toMatchObject({ code: 'TC773' });
    expect(await statuses('g-g')).toEqual([{ appId: 'explorer', status: 'REVOKED', revokedReason: 'grant_revoked', revoked: true }]);
  });

  test('a step-up revoked on its own can be approved again while the grant is ACTIVE, and not once it is revoked', async () => {
    await seedGrant('h');
    await addStepUp('g-h', 'explorer');
    await db.exec(`UPDATE "tinycloud_native_stepup" SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP, "revokedReason" = 'app_revoked' WHERE "grantId" = 'g-h'`);
    await db.exec(`UPDATE "tinycloud_native_stepup" SET "status" = 'ACTIVE', "revokedAt" = NULL, "revokedReason" = NULL WHERE "grantId" = 'g-h'`);
    expect((await statuses('g-h'))[0]?.status).toBe('ACTIVE');

    await db.exec(`UPDATE "tinycloud_native_stepup" SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP, "revokedReason" = 'app_revoked' WHERE "grantId" = 'g-h'`);
    await db.exec(`UPDATE "tinycloud_native_grant" SET "status" = 'REVOKED' WHERE "id" = 'g-h'`);
    await expect(db.exec(`UPDATE "tinycloud_native_stepup" SET "status" = 'ACTIVE' WHERE "grantId" = 'g-h'`)).rejects.toMatchObject({ code: 'TC773' });
  });

  test('down.sql leaves no step-up trigger, function or table behind', async () => {
    const scratch = new PGlite();
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) {
        await scratch.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
      await scratch.exec(await readFile(join(root, 'packages/db/prisma/migrations/20261121_0001_native_stepup/down.sql'), 'utf8'));
      const left = await scratch.query<{ name: string }>(
        `SELECT tgname AS name FROM pg_trigger WHERE tgname LIKE 'tinycloud_native_stepup%'
         UNION ALL SELECT proname FROM pg_proc WHERE proname LIKE 'tinycloud_native_stepup%'
         UNION ALL SELECT relname FROM pg_class WHERE relname LIKE 'tinycloud_native_stepup%'`,
      );
      expect(left.rows).toEqual([]);
    } finally {
      await scratch.close();
    }
  });

  test('one step-up per app per grant, a closed status set, and deleting the grant deletes the rows', async () => {
    await seedGrant('e');
    await addStepUp('g-e', 'explorer');
    await expect(addStepUp('g-e', 'explorer')).rejects.toThrow();
    await expect(db.exec(`UPDATE "tinycloud_native_stepup" SET "status" = 'PENDING' WHERE "grantId" = 'g-e'`)).rejects.toThrow();

    await db.exec(`DELETE FROM "tinycloud_native_grant" WHERE "id" = 'g-e'`);
    expect(await statuses('g-e')).toEqual([]);
  });
});
