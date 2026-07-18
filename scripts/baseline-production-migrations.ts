#!/usr/bin/env bun

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createPrismaClient } from '../packages/db/src/index';

const repoRoot = resolve(import.meta.dir, '..');
const migrationsDir = join(repoRoot, 'packages/db/prisma/migrations');
const baselineSchema = join(
  repoRoot,
  'packages/db/prisma/baselines/origin-main-44305b4.prisma'
);
const interruptedSchema = join(
  repoRoot,
  'packages/db/prisma/baselines/origin-main-44305b4-after-user-encryption.prisma'
);
const prismaBin = join(repoRoot, 'node_modules/.bin/prisma');
const confirmation = 'baseline-origin-main-44305b4';
const baselineSchemaSha256 =
  '8b8b8479e7b5381c92f142b25a3b1d4975236969ac7cc52a1020f161851170e4';
const interruptedSchemaSha256 =
  '7e355bc82f06666e5d8f20d85c1d476c0886f6a7fb4eaa83531f842f3cee3129';

const migrationInventory = [
  {
    name: '0_init',
    sha256: 'b8a48e0a10bda38007bfc729e4824eb0e76a25ef835fd8f897043b2651d5b310',
    dbPushEquivalent: true,
  },
  {
    name: '20260303_add_user_encryption_key',
    sha256: '3b15c1561998e4b3e9fdedb0a032879291b9d714b807c7717e490c57f111e012',
    dbPushEquivalent: false,
  },
  {
    name: '20260628_add_auto_sign_enabled',
    sha256: 'f6cda47dc0a1108c6e219ed4105771c790386acb84d030e4afcdc0e578af768b',
    dbPushEquivalent: true,
  },
  {
    name: '20260630_add_tinycloud_bootstrap_state',
    sha256: '2ec0e404864dffe7a4954b58cc6e46b37c30b80aa3bef940b2d3dfee4185be5c',
    dbPushEquivalent: true,
  },
  {
    name: '20260714_origin_main_schema_catchup',
    sha256: '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09',
    dbPushEquivalent: true,
  },
] as const;
const initMigration = '0_init';
const userEncryptionMigration = '20260303_add_user_encryption_key';
const autoSignMigration = '20260628_add_auto_sign_enabled';
const baselineCompletionMarker = '20260714_origin_main_schema_catchup';
const firstPendingMigration = '20260714_zz_origin_main_db_push_reconciliation';
const firstManagedAccountMigration =
  '20260715_0001_managed_accounts_phase_a_fix';

type MigrationRow = {
  migration_name: string;
  checksum: string;
  finished_at: Date | null;
  rolled_back_at: Date | null;
  applied_steps_count: number;
};

function requirePostgresUrl() {
  const value = process.env.DATABASE_URL;
  if (!value) {
    throw new Error('DATABASE_URL must be set');
  }
  if (!value.startsWith('postgresql://') && !value.startsWith('postgres://')) {
    throw new Error('DATABASE_URL must be a PostgreSQL connection string');
  }
}

function runPrisma(args: string[], allowedStatuses = [0]) {
  const result = spawnSync(process.execPath, [prismaBin, ...args], {
    cwd: repoRoot,
    env: process.env,
    encoding: 'utf8',
    stdio: 'pipe',
  });
  const status = result.status ?? 1;
  if (!allowedStatuses.includes(status)) {
    const output = [result.stdout, result.stderr]
      .filter(Boolean)
      .join('\n')
      .trim();
    throw new Error(
      `Prisma command failed: prisma ${args.join(' ')}${
        output ? `\n${output}` : ''
      }`
    );
  }
  return result;
}

function sha256(content: string) {
  return createHash('sha256').update(content).digest('hex');
}

async function assertFrozenInventory() {
  const snapshots = [
    [baselineSchema, baselineSchemaSha256],
    [interruptedSchema, interruptedSchemaSha256],
  ] as const;
  for (const [schemaPath, checksum] of snapshots) {
    if (sha256(await readFile(schemaPath, 'utf8')) !== checksum) {
      throw new Error(
        `Frozen production schema checksum does not match: ${schemaPath}`
      );
    }
  }

  for (const migration of migrationInventory) {
    const sql = await readFile(
      join(migrationsDir, migration.name, 'migration.sql'),
      'utf8'
    );
    if (sha256(sql) !== migration.sha256) {
      throw new Error(
        `Migration ${migration.name} changed after the production inventory was reviewed`
      );
    }
  }

  const entries = await readdir(migrationsDir, { withFileTypes: true });
  const names = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const expectedPrefix = [
    ...migrationInventory.map((migration) => migration.name),
    firstPendingMigration,
    firstManagedAccountMigration,
  ];
  const actualPrefix = names.slice(0, expectedPrefix.length);
  if (actualPrefix.join('\n') !== expectedPrefix.join('\n')) {
    throw new Error(
      `Migration history no longer has the reviewed production prefix.\nExpected:\n${expectedPrefix.join(
        '\n'
      )}\nActual:\n${actualPrefix.join('\n')}`
    );
  }
}

async function readMigrationHistory() {
  const prisma = createPrismaClient({
    connectionString: process.env.DATABASE_URL,
  });
  try {
    const table = await prisma.$queryRaw<Array<{ exists: boolean }>>`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = '_prisma_migrations'
      ) AS "exists"
    `;
    if (!table[0]?.exists) {
      return [];
    }
    return await prisma.$queryRawUnsafe<Array<MigrationRow>>(
      'SELECT migration_name, checksum, finished_at, rolled_back_at, applied_steps_count FROM "_prisma_migrations" ORDER BY started_at'
    );
  } finally {
    await prisma.$disconnect();
  }
}

function assertKnownChecksums(history: MigrationRow[]) {
  const checksums = new Map(
    migrationInventory.map((migration) => [migration.name, migration.sha256])
  );
  for (const row of history) {
    const expected = checksums.get(
      row.migration_name as (typeof migrationInventory)[number]['name']
    );
    if (!expected || row.checksum !== expected) {
      throw new Error(
        `Unexpected migration record or checksum: ${row.migration_name}`
      );
    }
  }
}

function sameNames(rows: MigrationRow[], expected: string[]) {
  const actual = rows.map((row) => row.migration_name).sort();
  return actual.join('\n') === [...expected].sort().join('\n');
}

function classifyHistory(history: MigrationRow[]) {
  assertKnownChecksums(history);
  const successful = history.filter(
    (row) => row.finished_at && !row.rolled_back_at
  );
  const activeFailures = history.filter(
    (row) => !row.finished_at && !row.rolled_back_at
  );
  const rolledBack = history.filter((row) => row.rolled_back_at);
  const dbPushNames = migrationInventory
    .filter((migration) => migration.dbPushEquivalent)
    .map((migration) => migration.name);
  const pristineProgressStates = [
    [],
    [initMigration],
    [initMigration, autoSignMigration],
    [
      initMigration,
      autoSignMigration,
      '20260630_add_tinycloud_bootstrap_state',
    ],
    [...dbPushNames],
  ];

  const isPristineBaseline =
    activeFailures.length === 0 &&
    rolledBack.length === 0 &&
    pristineProgressStates.some((names) => sameNames(successful, names));
  if (isPristineBaseline) {
    return { kind: 'db-push' as const, schema: baselineSchema };
  }

  const incidentSuccesses = [initMigration, userEncryptionMigration];
  const exactIncident =
    sameNames(successful, incidentSuccesses) &&
    activeFailures.length === 1 &&
    activeFailures[0]?.migration_name === autoSignMigration &&
    activeFailures[0].applied_steps_count === 0 &&
    rolledBack.length === 0;
  if (exactIncident) {
    return { kind: 'interrupted' as const, schema: interruptedSchema };
  }

  const resumedSuccesses = [
    initMigration,
    userEncryptionMigration,
    autoSignMigration,
  ];
  const resumedAllowedSuccesses = new Set([
    ...dbPushNames,
    userEncryptionMigration,
  ]);
  const exactResolvedIncident =
    new Set(successful.map((row) => row.migration_name)).size ===
      successful.length &&
    resumedSuccesses.every((name) =>
      successful.some((row) => row.migration_name === name)
    ) &&
    successful.every((row) =>
      resumedAllowedSuccesses.has(row.migration_name)
    ) &&
    activeFailures.length === 0 &&
    rolledBack.length === 1 &&
    rolledBack[0]?.migration_name === autoSignMigration &&
    rolledBack[0].applied_steps_count === 0;
  if (exactResolvedIncident) {
    return { kind: 'interrupted-resolved' as const, schema: interruptedSchema };
  }

  throw new Error(
    'Migration history is not an approved db-push baseline or the exact reviewed 20260628 interruption'
  );
}

function assertPhysicalSchema(schema: string) {
  const diff = runPrisma(
    [
      'migrate',
      'diff',
      '--from-schema',
      schema,
      '--to-config-datasource',
      '--exit-code',
    ],
    [0, 2]
  );
  if (diff.status === 2) {
    const details = [diff.stdout, diff.stderr]
      .filter(Boolean)
      .join('\n')
      .trim();
    throw new Error(
      `Production schema does not match the approved recovery snapshot. No migration records were changed.${
        details ? `\n${details}` : ''
      }`
    );
  }
}

async function main() {
  if (process.env.OPENKEY_BASELINE_CONFIRMATION !== confirmation) {
    throw new Error(
      `Set OPENKEY_BASELINE_CONFIRMATION exactly to ${confirmation}`
    );
  }
  requirePostgresUrl();
  await assertFrozenInventory();

  const history = await readMigrationHistory();
  const state = classifyHistory(history);
  assertPhysicalSchema(state.schema);

  if (state.kind === 'interrupted') {
    runPrisma(['migrate', 'resolve', '--applied', autoSignMigration]);
    console.log(
      `Resolved exact failed migration as applied: ${autoSignMigration}`
    );
  }

  const refreshedHistory = await readMigrationHistory();
  const successful = new Set(
    refreshedHistory
      .filter((row) => row.finished_at && !row.rolled_back_at)
      .map((row) => row.migration_name)
  );
  for (const migration of migrationInventory.filter(
    (entry) => entry.dbPushEquivalent
  )) {
    if (successful.has(migration.name)) {
      console.log(`Already recorded: ${migration.name}`);
      continue;
    }
    runPrisma(['migrate', 'resolve', '--applied', migration.name]);
    console.log(`Recorded db-push-equivalent migration: ${migration.name}`);
  }

  const finalHistory = await readMigrationHistory();
  const activeFailures = finalHistory.filter(
    (row) => !row.finished_at && !row.rolled_back_at
  );
  const marker = finalHistory.some(
    (row) =>
      row.migration_name === baselineCompletionMarker &&
      row.checksum ===
        migrationInventory.find(
          (entry) => entry.name === baselineCompletionMarker
        )?.sha256 &&
      row.finished_at &&
      !row.rolled_back_at
  );
  if (!marker || activeFailures.length > 0) {
    throw new Error('Baseline completion marker was not recorded cleanly');
  }

  console.log(
    'Production baseline completion marker recorded; production migration deploy is now unlocked.'
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
