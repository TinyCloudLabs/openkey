import { expect, test } from 'bun:test';
import {
  checkRuntimeSchemaContract,
  requiredRuntimeMigrationChecksums,
  type MigrationRecord,
} from './schema-contract';

const validRows: MigrationRecord[] = [...requiredRuntimeMigrationChecksums].map(([migration_name, checksum]) => ({
  migration_name,
  checksum,
  finished_at: new Date('2026-08-22T00:00:00.000Z'),
  rolled_back_at: null,
}));

function database(rows: MigrationRecord[]) {
  return { $queryRawUnsafe: async <T>() => rows as T };
}

test('fails for a missing migration required by the candidate Prisma client', async () => {
  expect(await checkRuntimeSchemaContract(database(validRows.slice(1)))).toEqual({
    ready: false,
    reason: 'migration-missing',
  });
});

test('fails for unfinished, rolled-back, and checksum-mismatched required migrations', async () => {
  expect(await checkRuntimeSchemaContract(database([{ ...validRows[0], finished_at: null }, ...validRows.slice(1)]))).toEqual({
    ready: false,
    reason: 'migration-unfinished',
  });
  expect(await checkRuntimeSchemaContract(database([{ ...validRows[0], rolled_back_at: new Date() }, ...validRows.slice(1)]))).toEqual({
    ready: false,
    reason: 'migration-rolled-back',
  });
  expect(await checkRuntimeSchemaContract(database([{ ...validRows[0], checksum: 'mismatch' }, ...validRows.slice(1)]))).toEqual({
    ready: false,
    reason: 'migration-checksum-mismatch',
  });
});

test('accepts the required contract while destructive TC-488 remains pending', async () => {
  expect(await checkRuntimeSchemaContract(database(validRows))).toEqual({ ready: true });
});
