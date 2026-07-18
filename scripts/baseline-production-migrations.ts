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
const prismaBin = join(repoRoot, 'node_modules/.bin/prisma');
const confirmation = 'baseline-origin-main-44305b4';
const baselineSchemaSha256 =
  '8b8b8479e7b5381c92f142b25a3b1d4975236969ac7cc52a1020f161851170e4';

// This inventory records whether each migration's application-schema effect is
// present in a database produced by `prisma db push` from origin/main 44305b4.
// Only migrations whose complete effect is present may be marked as applied.
const migrationInventory = [
  {
    name: '0_init',
    sha256: 'b8a48e0a10bda38007bfc729e4824eb0e76a25ef835fd8f897043b2651d5b310',
    markApplied: true,
  },
  {
    name: '20260303_add_user_encryption_key',
    sha256: '3b15c1561998e4b3e9fdedb0a032879291b9d714b807c7717e490c57f111e012',
    markApplied: false,
  },
  {
    name: '20260628_add_auto_sign_enabled',
    sha256: 'f6cda47dc0a1108c6e219ed4105771c790386acb84d030e4afcdc0e578af768b',
    markApplied: true,
  },
  {
    name: '20260630_add_tinycloud_bootstrap_state',
    sha256: '2ec0e404864dffe7a4954b58cc6e46b37c30b80aa3bef940b2d3dfee4185be5c',
    markApplied: true,
  },
  {
    name: '20260714_origin_main_schema_catchup',
    sha256: '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09',
    markApplied: true,
  },
] as const;
const firstPendingMigration = '20260714_zz_origin_main_db_push_reconciliation';
const firstManagedAccountMigration =
  '20260715_0001_managed_accounts_phase_a_fix';

function requirePostgresUrl() {
  const value = process.env.DATABASE_URL;
  if (!value) {
    throw new Error('DATABASE_URL must be set');
  }
  if (!value.startsWith('postgresql://') && !value.startsWith('postgres://')) {
    throw new Error('DATABASE_URL must be a PostgreSQL connection string');
  }
  return value;
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
  const schema = await readFile(baselineSchema, 'utf8');
  if (sha256(schema) !== baselineSchemaSha256) {
    throw new Error(
      'Frozen origin/main baseline schema checksum does not match its reviewed value'
    );
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
    return await prisma.$queryRawUnsafe<
      Array<{
        migration_name: string;
        finished_at: Date | null;
        rolled_back_at: Date | null;
      }>
    >(
      'SELECT migration_name, finished_at, rolled_back_at FROM "_prisma_migrations" ORDER BY started_at'
    );
  } finally {
    await prisma.$disconnect();
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

  const migrationsToRecord = migrationInventory.filter(
    (migration) => migration.markApplied
  );
  const recordableNames = new Set<string>(
    migrationsToRecord.map((migration) => migration.name)
  );
  const history = await readMigrationHistory();
  for (const row of history) {
    if (!recordableNames.has(row.migration_name)) {
      throw new Error(
        `Database already records non-baseline migration ${row.migration_name}; use the normal migration deploy path`
      );
    }
    if (!row.finished_at || row.rolled_back_at) {
      throw new Error(
        `Migration ${row.migration_name} is not successfully applied; resolve it manually before baselining`
      );
    }
  }

  const diff = runPrisma(
    [
      'migrate',
      'diff',
      '--from-schema',
      baselineSchema,
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
      `Production schema does not match the frozen origin/main 44305b4 db-push schema. No migrations were marked applied.${
        details ? `\n${details}` : ''
      }`
    );
  }

  const alreadyApplied = new Set(history.map((row) => row.migration_name));
  for (const migration of migrationsToRecord) {
    if (alreadyApplied.has(migration.name)) {
      console.log(`Already recorded: ${migration.name}`);
      continue;
    }
    runPrisma(['migrate', 'resolve', '--applied', migration.name]);
    console.log(`Recorded db-push-equivalent migration: ${migration.name}`);
  }

  console.log(
    'Origin/main db-push baseline recorded. Pending migrations must now run with prisma migrate deploy.'
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
