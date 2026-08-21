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
    })).toBe('pre-tc488-device-only');
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
