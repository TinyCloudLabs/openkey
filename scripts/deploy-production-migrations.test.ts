import { describe, expect, test } from 'bun:test';
import {
  partitionPreTc488Migrations,
  selectProductionMigrationMode,
  type MigrationRow,
} from './deploy-production-migrations';

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

  test('fails closed if another migration is pending before TC-488', () => {
    expect(() => selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: [baseline.migration_name, ...tc492, device, '20260815_unreviewed'],
      managedAccountTableExists: true,
    })).toThrow('unreviewed pending migration set');
  });

  test('fails closed on inconsistent physical cutover state', () => {
    expect(() => selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: [baseline.migration_name, ...tc492, device],
      managedAccountTableExists: false,
    })).toThrow('history and physical custody schema disagree');
  });
});
