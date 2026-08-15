import { describe, expect, test } from 'bun:test';
import {
  assertDeviceAuthorizationPhysicalSchema,
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

const physicalDeviceAuthorizationSchema = () => ({
  columns: [
    ['id', 'text', false], ['userCode', 'text', false], ['deviceSecretHash', 'text', false],
    ['codeChallenge', 'text', false], ['sessionDid', 'text', false], ['publicJwk', 'jsonb', false],
    ['relayPublicJwk', 'jsonb', false], ['permissions', 'jsonb', false], ['nodeOrigin', 'text', false],
    ['shareOrigin', 'text', false], ['delegationExpiresAt', 'timestamp(3) without time zone', false],
    ['transactionExpiresAt', 'timestamp(3) without time zone', false], ['requestedAt', 'timestamp(3) without time zone', false, 'CURRENT_TIMESTAMP'],
    ['requestIpHash', 'text', false], ['nextPollAt', 'timestamp(3) without time zone', false],
    ['pollIntervalSeconds', 'integer', false], ['status', 'text', false, "'PENDING'::text"],
    ['approvedByUserId', 'text', true], ['encryptedResult', 'text', true], ['consumedAt', 'timestamp(3) without time zone', true],
    ['updatedAt', 'timestamp(3) without time zone', false],
  ].map(([name, type, nullable, defaultValue]) => ({ name, type, nullable, default: defaultValue ?? null })),
  indexes: [
    'UNIQUE INDEX "device_authorization_userCode_key" ON public.device_authorization USING btree ("userCode")',
    'INDEX "device_authorization_requestIpHash_requestedAt_idx" ON public.device_authorization USING btree ("requestIpHash", "requestedAt")',
    'INDEX "device_authorization_status_transactionExpiresAt_idx" ON public.device_authorization USING btree (status, "transactionExpiresAt")',
  ],
  foreignKey: 'FOREIGN KEY ("approvedByUserId") REFERENCES "user"(id) ON UPDATE CASCADE ON DELETE SET NULL',
});

describe('production migration deployment mode', () => {
  test('accepts the exact additive device-authorization physical runtime contract', () => {
    expect(() => assertDeviceAuthorizationPhysicalSchema(physicalDeviceAuthorizationSchema())).not.toThrow();
  });

  test('rejects a physical schema missing a runtime-required device column', () => {
    const physical = physicalDeviceAuthorizationSchema();
    physical.columns = physical.columns.filter((column) => column.name !== 'relayPublicJwk');
    expect(() => assertDeviceAuthorizationPhysicalSchema(physical)).toThrow('column count differs');
  });

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

  test('allows only the additive device migration before TC-488', () => {
    expect(selectProductionMigrationMode({
      migrations: [baseline],
      migrationDirectories: [baseline.migration_name, ...tc492, device],
      managedAccountTableExists: true,
    })).toBe('pre-tc488-device-only');
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
