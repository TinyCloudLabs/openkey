import { expect, test } from 'bun:test';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import {
  checkRuntimeSchemaContract,
  allowedPendingDestructiveMigrations,
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

test('fails when a required migration retains an unresolved earlier attempt', async () => {
  expect(await checkRuntimeSchemaContract(database([...validRows, { ...validRows[0], finished_at: null }]))).toEqual({
    ready: false,
    reason: 'migration-unfinished',
  });
});

test('fails closed when the migration query cannot run', async () => {
  const unavailable = { $queryRawUnsafe: async <T>() => { throw new Error('database unavailable') as T; } };
  expect(await checkRuntimeSchemaContract(unavailable)).toEqual({ ready: false, reason: 'migration-query-failed' });
});

test('accepts the required contract while destructive TC-488 remains pending', async () => {
  expect(await checkRuntimeSchemaContract(database(validRows))).toEqual({ ready: true });
});

test('covers every committed post-baseline migration except the explicit TC-488 gate', async () => {
  const migrationDirectory = join(import.meta.dir, '../prisma/migrations');
  const committed = (await readdir(migrationDirectory, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && entry.name >= '20260714_origin_main_schema_catchup')
    .map((entry) => entry.name)
    .filter((name) => !allowedPendingDestructiveMigrations.has(name))
    .sort();

  expect([...requiredRuntimeMigrationChecksums.keys()].sort()).toEqual(committed);
});
