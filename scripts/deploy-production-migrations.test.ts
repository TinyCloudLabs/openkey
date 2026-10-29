import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  partitionPreTc488Migrations,
  selectProductionMigrationMode,
  type MigrationRow,
} from './deploy-production-migrations';
import { requiredRuntimeMigrationChecksums } from '../packages/db/src/schema-contract';

const baseline: MigrationRow = {
  migration_name: '20260714_origin_main_schema_catchup',
  checksum: '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09',
  finished_at: new Date(),
  rolled_back_at: null,
};
const tc488 = '20260806_0002_remove_organization_key_custody';
const device = '20260814_0001_share_device_authorization';
const broker = '20261005_0001_delegation_code_broker';
const native = '20261007_0001_tinycloud_native_foundation';
const nativeHost = '20261007_0002_native_preparation_host';
const nativeTokenGuard = '20261007_0003_tinycloud_native_token_guard';
const signinPolish = '20261012_0001_signin_polish_hints_branding';
const tc492 = [
  '20260805_0001_canonical_tinycloud_key',
  '20260805_0002_tinycloud_manage_key_app_preferences',
  '20260805_0003_tinycloud_manage_key_global_preference',
  '20260806_0001_tinycloud_manage_key_lifecycle',
  tc488,
];

describe('production migration deployment mode', () => {
  test('uses the normal full deployment after the authorized TC-488 cutover', () => {
    expect(selectProductionMigrationMode({
      migrations: [baseline, {
        migration_name: tc488,
        checksum: 'reviewed-by-the-existing-cutover-guard',
        finished_at: new Date(),
        rolled_back_at: null,
      }],
      migrationDirectories: [baseline.migration_name, ...tc492, device],
      managedAccountTableExists: false,
    })).toBe('full');
  });

  test('allows the four reviewed additive TC-492 migrations before TC-488', () => {
    expect(selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: [baseline.migration_name, ...tc492, device],
      managedAccountTableExists: true,
    })).toBe('pre-tc488-additive');
  });

  test('parks only the destructive TC-488 migration and applies every reviewed additive migration', () => {
    const { apply, park } = partitionPreTc488Migrations([...tc492, device]);

    expect(apply).toEqual([
      '20260805_0001_canonical_tinycloud_key',
      '20260805_0002_tinycloud_manage_key_app_preferences',
      '20260805_0003_tinycloud_manage_key_global_preference',
      '20260806_0001_tinycloud_manage_key_lifecycle',
      device,
    ]);
    expect(park).toEqual([tc488]);
  });

  test('permits the reviewed broker table while TC-488 remains parked', () => {
    const directories = [baseline.migration_name, ...tc492, device, broker];
    expect(selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toBe('pre-tc488-additive');
    expect(partitionPreTc488Migrations([...tc492, device, broker])).toEqual({
      apply: [...tc492.filter((name) => name !== tc488), device, broker],
      park: [tc488],
    });
    expect(() => selectProductionMigrationMode({
      migrations: [baseline, {
        migration_name: broker,
        checksum: 'unreviewed',
        finished_at: new Date(),
        rolled_back_at: null,
      }],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toThrow(`Stored migration checksum differs from the reviewed ${broker}`);
  });

  test('permits the reviewed TC-773 native delegation foundation while TC-488 remains parked', () => {
    const directories = [baseline.migration_name, ...tc492, device, broker, native];
    expect(selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toBe('pre-tc488-additive');
    expect(partitionPreTc488Migrations([...tc492, device, broker, native])).toEqual({
      apply: [...tc492.filter((name) => name !== tc488), device, broker, native],
      park: [tc488],
    });
    expect(() => selectProductionMigrationMode({
      migrations: [baseline, {
        migration_name: native,
        checksum: 'unreviewed',
        finished_at: new Date(),
        rolled_back_at: null,
      }],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toThrow(`Stored migration checksum differs from the reviewed ${native}`);
  });

  test('permits the reviewed O3 preparation-host migration while TC-488 remains parked', () => {
    const directories = [baseline.migration_name, ...tc492, device, broker, native, nativeHost];
    expect(selectProductionMigrationMode({
      migrations: [baseline], migrationDirectories: directories, managedAccountTableExists: true,
    })).toBe('pre-tc488-additive');
    expect(partitionPreTc488Migrations([...tc492, device, broker, native, nativeHost])).toEqual({
      apply: [...tc492.filter((name) => name !== tc488), device, broker, native, nativeHost],
      park: [tc488],
    });
    expect(() => selectProductionMigrationMode({
      migrations: [baseline, {
        migration_name: nativeHost, checksum: 'unreviewed', finished_at: new Date(), rolled_back_at: null,
      }],
      migrationDirectories: directories, managedAccountTableExists: true,
    })).toThrow(`Stored migration checksum differs from the reviewed ${nativeHost}`);
  });

  test('permits the reviewed TC-773 native token guard triggers while TC-488 remains parked', () => {
    const directories = [baseline.migration_name, ...tc492, device, broker, native, nativeHost, nativeTokenGuard];
    expect(selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toBe('pre-tc488-additive');
    expect(partitionPreTc488Migrations([...tc492, device, broker, native, nativeHost, nativeTokenGuard])).toEqual({
      apply: [...tc492.filter((name) => name !== tc488), device, broker, native, nativeHost, nativeTokenGuard],
      park: [tc488],
    });
    expect(() => selectProductionMigrationMode({
      migrations: [baseline, {
        migration_name: nativeTokenGuard,
        checksum: 'unreviewed',
        finished_at: new Date(),
        rolled_back_at: null,
      }],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toThrow(`Stored migration checksum differs from the reviewed ${nativeTokenGuard}`);
  });

  test('permits the prepared SIWE handoff migration while TC-488 remains parked', async () => {
    const name = '20261016_0001_prepared_siwe_handoff';
    const directories = [baseline.migration_name, ...tc492, device, name];
    expect(selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toBe('pre-tc488-additive');
    expect(partitionPreTc488Migrations([...tc492, device, name])).toEqual({
      apply: [...tc492.filter((entry) => entry !== tc488), device, name],
      park: [tc488],
    });
    const checksum = createHash('sha256').update(await readFile(
      join(import.meta.dir, '../packages/db/prisma/migrations', name, 'migration.sql'),
    )).digest('hex');
    expect(checksum).toBe('645d931e10dbd068da7f7243dcbe995f1af6f0e339b98d082264c8153bfec9ec');
    expect(() => selectProductionMigrationMode({
      migrations: [baseline, { migration_name: name, checksum: 'unreviewed', finished_at: new Date(), rolled_back_at: null }],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toThrow(`Stored migration checksum differs from the reviewed ${name}`);
  });

  test('permits the reviewed org custody migration while TC-488 remains parked', async () => {
    const name = '20261021_0001_org_key_custody';
    const directories = [baseline.migration_name, ...tc492, device, signinPolish, name];
    expect(selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toBe('pre-tc488-additive');
    expect(partitionPreTc488Migrations([...tc492, device, signinPolish, name])).toEqual({
      apply: [...tc492.filter((entry) => entry !== tc488), device, signinPolish, name],
      park: [tc488],
    });
    const checksum = createHash('sha256').update(await readFile(
      join(import.meta.dir, '../packages/db/prisma/migrations', name, 'migration.sql'),
    )).digest('hex');
    expect(checksum).toBe('2c9f0a53affc841a7f0a7d1b6f8b865f4c4ef0277e0e140e1f81cd76f1d97f23');
    expect(() => selectProductionMigrationMode({
      migrations: [baseline, { migration_name: name, checksum: 'unreviewed', finished_at: new Date(), rolled_back_at: null }],
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toThrow(`Stored migration checksum differs from the reviewed ${name}`);
  });

  test('permits registration receipts before TC-488 and refuses changed applied bytes', async () => {
    const name = '20261029_0001_org_registration_proofs';
    const checksum = createHash('sha256').update(await readFile(
      join(import.meta.dir, '../packages/db/prisma/migrations', name, 'migration.sql'),
    )).digest('hex');
    expect(checksum).toBe('2aba2adcbca2a1554b480ee832873d846ed57161f95668ff4b4ce6659f465569');
    expect(requiredRuntimeMigrationChecksums.get(name)).toBe(checksum);
    const directories = [baseline.migration_name, ...tc492, device, name];
    expect(selectProductionMigrationMode({
      migrations: [baseline], migrationDirectories: directories, managedAccountTableExists: true,
    })).toBe('pre-tc488-additive');
    expect(partitionPreTc488Migrations(directories)).toEqual({
      apply: directories.filter((entry) => entry !== tc488), park: [tc488],
    });
    expect(() => selectProductionMigrationMode({
      migrations: [baseline, { migration_name: name, checksum: 'unreviewed', finished_at: new Date(), rolled_back_at: null }],
      migrationDirectories: directories, managedAccountTableExists: true,
    })).toThrow(`Stored migration checksum differs from the reviewed ${name}`);
  });

  test('accepts the real sign-in polish migration in the branch migration list before TC-488', async () => {
    const migrationsRoot = join(import.meta.dir, '../packages/db/prisma/migrations');
    const directories = (await readdir(migrationsRoot, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    const history: MigrationRow[] = [];
    for (const name of directories.filter((name) => name !== tc488 && name !== signinPolish)) {
      const checksum = createHash('sha256')
        .update(await readFile(join(migrationsRoot, name, 'migration.sql'))).digest('hex');
      history.push({ migration_name: name, checksum, finished_at: new Date(), rolled_back_at: null });
    }
    expect(selectProductionMigrationMode({
      migrations: history,
      migrationDirectories: directories,
      managedAccountTableExists: true,
    })).toBe('pre-tc488-additive');
  });

  test('fails closed if another migration is pending before TC-488', () => {
    expect(() => selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: [baseline.migration_name, ...tc492, device, '20260815_unreviewed'],
      managedAccountTableExists: true,
    })).toThrow('unreviewed pending migration set');
  });

  describe('the revoked access token table (TC-2104)', () => {
    const name = '20261026_0001_revoked_access_token';
    const migrationsRoot = join(import.meta.dir, '../packages/db/prisma/migrations');
    const fileChecksum = async (migration: string) =>
      createHash('sha256').update(await readFile(join(migrationsRoot, migration, 'migration.sql'))).digest('hex');
    const applied = (migration_name: string, checksum: string): MigrationRow =>
      ({ migration_name, checksum, finished_at: new Date(), rolled_back_at: null });
    const directories = [baseline.migration_name, ...tc492, device, name];

    test('is pending beside the parked TC-488 migration: the additive mode, and only the new one is applied', () => {
      expect(selectProductionMigrationMode({
        migrations: [baseline],
        migrationDirectories: directories,
        managedAccountTableExists: true,
      })).toBe('pre-tc488-additive');
      const { apply, park } = partitionPreTc488Migrations([tc488, name]);
      expect(apply).toEqual([name]);
      expect(park).toEqual([tc488]);
    });

    test('TC-488 is never in the list to apply, whatever else is pending', () => {
      const { apply, park } = partitionPreTc488Migrations([...tc492, device, name]);
      expect(apply).not.toContain(tc488);
      expect(apply).toContain(name);
      expect(park).toEqual([tc488]);
    });

    test('another unknown migration pending with it still fails closed', () => {
      expect(() => selectProductionMigrationMode({
        migrations: [baseline],
        migrationDirectories: [...directories, '20261027_0001_not_reviewed'],
        managedAccountTableExists: true,
      })).toThrow('unreviewed pending migration set');
    });

    test('a stored checksum that differs from the reviewed one is refused', () => {
      expect(() => selectProductionMigrationMode({
        migrations: [baseline, applied(name, 'unreviewed')],
        migrationDirectories: directories,
        managedAccountTableExists: true,
      })).toThrow(`Stored migration checksum differs from the reviewed ${name}`);
    });

    test('the reviewed checksum is the one of the migration file, and the runtime schema contract records the same', async () => {
      const checksum = await fileChecksum(name);
      expect(checksum).toBe('a57958f43b7d1c28c25b38ef358a5392e4b7f9ecf78a979b2c86c8027bd53a30');
      expect(requiredRuntimeMigrationChecksums.get(name)).toBe(checksum);
      // Applied with the file's own checksum, the reviewed list accepts it: an edit of either one fails here.
      expect(selectProductionMigrationMode({
        migrations: [baseline, applied(name, checksum)],
        migrationDirectories: directories,
        managedAccountTableExists: true,
      })).toBe('pre-tc488-additive');
    });

    test('every migration directory newer than the parked TC-488 one is reviewed for the pre-TC-488 deploy', async () => {
      const all = (await readdir(migrationsRoot, { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      const newer = all.filter((migration) => migration > tc488);
      expect(newer).toContain(name);
      for (const pendingOne of newer) {
        const history: MigrationRow[] = [];
        for (const migration of all.filter((other) => other !== tc488 && other !== pendingOne)) {
          history.push(applied(migration, await fileChecksum(migration)));
        }
        expect(selectProductionMigrationMode({
          migrations: history,
          migrationDirectories: all,
          managedAccountTableExists: true,
        }), `${pendingOne} is not in the reviewed list of scripts/deploy-production-migrations.ts`).toBe('pre-tc488-additive');
      }
    });
  });

  test('fails closed on inconsistent physical cutover state', () => {
    expect(() => selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: [baseline.migration_name, ...tc492, device],
      managedAccountTableExists: false,
    })).toThrow('history and physical custody schema disagree');
  });
});
