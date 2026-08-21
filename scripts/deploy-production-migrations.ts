#!/usr/bin/env bun

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rename, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createPrismaClient } from '../packages/db/src/index';

const repoRoot = resolve(import.meta.dir, '..');
const migrationsDir = join(repoRoot, 'packages/db/prisma/migrations');
const prismaSchema = join(repoRoot, 'packages/db/prisma/schema.prisma');
const prismaBin = join(repoRoot, 'node_modules/.bin/prisma');

const baselineMigration = '20260714_origin_main_schema_catchup';
const baselineChecksum = '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09';
const tc488Migration = '20260806_0002_remove_organization_key_custody';
const tc492AdditiveMigrations: ReadonlyMap<string, string> = new Map([
  ['20260805_0001_canonical_tinycloud_key', '65b81dce28ab9dc8847defa78f986abe000243cfd027879238f55efee825cfae'],
  ['20260805_0002_tinycloud_manage_key_app_preferences', '035b642532adfc98351141a578ff675c5f67fbde41da6e208e8d3bbbc336d972'],
  ['20260805_0003_tinycloud_manage_key_global_preference', '4cf2225e80626f98b826225fbed45f6166b10ec7c3999dcb7b272ae2da06ab0e'],
  ['20260806_0001_tinycloud_manage_key_lifecycle', '2ae19ab7c9267d704d17578c8613c17b737d1706acc0b2e48dd3f4a4661d35bd'],
]);
const deviceMigration = '20260814_0001_share_device_authorization';
const deviceChecksum = '81bc814a59b2d7604c5d40490e1c96290a7532b70751c60b44b60e3e4b1e199a';

export type MigrationRow = {
  migration_name: string;
  checksum: string;
  finished_at: Date | null;
  rolled_back_at: Date | null;
};

export function selectProductionMigrationMode(input: {
  migrations: MigrationRow[];
  migrationDirectories: string[];
  managedAccountTableExists: boolean;
}): 'full' | 'pre-tc488-device-only' {
  const { migrations, migrationDirectories, managedAccountTableExists } = input;
  const baseline = migrations.find((row) => row.migration_name === baselineMigration);
  if (!baseline?.finished_at || baseline.rolled_back_at || baseline.checksum !== baselineChecksum) {
    throw new Error(`Production baseline marker ${baselineMigration} is missing or invalid`);
  }

  const unresolved = migrations.filter((row) => !row.finished_at && !row.rolled_back_at);
  if (unresolved.length > 0) {
    throw new Error(`Production has unresolved failed migrations: ${unresolved.map((row) => row.migration_name).join(', ')}`);
  }

  const successful = new Set(
    migrations
      .filter((row) => row.finished_at && !row.rolled_back_at)
      .map((row) => row.migration_name),
  );
  const tc488Applied = successful.has(tc488Migration);
  if (tc488Applied && !managedAccountTableExists) return 'full';
  if (tc488Applied || !managedAccountTableExists) {
    throw new Error('Production TC-488 migration history and physical custody schema disagree');
  }

  const knownDirectories = new Set(migrationDirectories);
  const unknownHistory = migrations.filter((row) => !knownDirectories.has(row.migration_name));
  if (unknownHistory.length > 0) {
    throw new Error(`Production contains migration history absent from this checkout: ${unknownHistory.map((row) => row.migration_name).join(', ')}`);
  }

  const pending = migrationDirectories.filter((name) => !successful.has(name));
  const unexpectedPending = pending.filter((name) => !tc492AdditiveMigrations.has(name) && name !== tc488Migration && name !== deviceMigration);
  if (
    unexpectedPending.length > 0 ||
    !pending.includes(tc488Migration) ||
    !pending.every((name) => tc492AdditiveMigrations.has(name) || name === tc488Migration || name === deviceMigration)
  ) {
    throw new Error(`Pre-TC-488 production has an unreviewed pending migration set: ${pending.join(', ')}`);
  }

  for (const [name, checksum] of tc492AdditiveMigrations) {
    const applied = migrations.find(
      (row) => row.migration_name === name && row.finished_at && !row.rolled_back_at,
    );
    if (applied && applied.checksum !== checksum) {
      throw new Error(`Stored migration checksum differs from the reviewed ${name}`);
    }
  }

  const appliedDevice = migrations.find(
    (row) => row.migration_name === deviceMigration && row.finished_at && !row.rolled_back_at,
  );
  if (appliedDevice && appliedDevice.checksum !== deviceChecksum) {
    throw new Error(`Stored migration checksum differs from the reviewed ${deviceMigration}`);
  }
  return 'pre-tc488-device-only';
}

export function partitionPreTc488Migrations(pendingMigrations: string[]) {
  return {
    apply: pendingMigrations.filter((name) => name !== tc488Migration),
    park: pendingMigrations.filter((name) => name === tc488Migration),
  };
}

function requirePostgresUrl() {
  const value = process.env.DATABASE_URL;
  if (!value?.match(/^postgres(ql)?:\/\//)) {
    throw new Error('Production migration deployment requires a PostgreSQL DATABASE_URL');
  }
}

function run(command: string, args: string[]) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env: process.env,
    encoding: 'utf8',
    stdio: 'inherit',
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} exited with status ${result.status ?? 1}`);
  }
}

function runBunScript(script: string) {
  run(process.execPath, ['run', script]);
}

async function sha256(path: string): Promise<string> {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

async function assertReviewedMigrationFiles() {
  const reviewed = [
    ...tc492AdditiveMigrations,
    [tc488Migration, 'ecf68b38f136da32292c250566d3094d1f8eb0b89c855fd8543adf4544ec7ac6'],
    [deviceMigration, deviceChecksum],
  ] as const;
  for (const [name, expected] of reviewed) {
    const actual = await sha256(join(migrationsDir, name, 'migration.sql'));
    if (actual !== expected) throw new Error(`Reviewed migration checksum mismatch: ${name}`);
  }
}

async function readState(database: ReturnType<typeof createPrismaClient>) {
  const migrations = await database.$queryRawUnsafe<MigrationRow[]>(
    'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" ORDER BY migration_name',
  );
  const managedAccount = await database.$queryRaw<Array<{ exists: boolean }>>`
    SELECT to_regclass('public.managed_account') IS NOT NULL AS "exists"
  `;
  const migrationDirectories = (await readdir(migrationsDir, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  return {
    migrations,
    migrationDirectories,
    managedAccountTableExists: managedAccount[0]?.exists === true,
  };
}

async function deployAdditiveMigrationsBeforeTc488(
  database: ReturnType<typeof createPrismaClient>,
  pendingMigrations: string[],
) {
  const { apply: pendingAdditive, park: parkedMigrations } = partitionPreTc488Migrations(pendingMigrations);
  if (pendingAdditive.length > 0) {
    const temporaryRoot = await mkdtemp(join(tmpdir(), 'openkey-pre-tc488-'));
    const movedMigrations: string[] = [];
    try {
      for (const name of parkedMigrations) {
        await rename(join(migrationsDir, name), join(temporaryRoot, name));
        movedMigrations.push(name);
      }
      // Prisma has no single-migration flag. The destructive custody cutover
      // is the only parked entry; the reviewed expand migrations remain visible
      // to the normal engine and are applied in their migration order.
      run(process.execPath, [prismaBin, 'migrate', 'deploy', '--schema', prismaSchema]);
    } finally {
      for (const name of movedMigrations.reverse()) {
        await rename(join(temporaryRoot, name), join(migrationsDir, name));
      }
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }

  const rows = await database.$queryRawUnsafe<MigrationRow[]>(
    'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" WHERE migration_name = ANY($1::text[])',
    [...tc492AdditiveMigrations.keys(), deviceMigration],
  );
  const expected = new Map([...tc492AdditiveMigrations, [deviceMigration, deviceChecksum]]);
  for (const [name, checksum] of expected) {
    const row = rows.find((candidate) => candidate.migration_name === name);
    if (!row?.finished_at || row.rolled_back_at || row.checksum !== checksum) {
      throw new Error(`${name} was not recorded with the reviewed checksum`);
    }
  }

  const physical = await database.$queryRawUnsafe<Array<{
    user_tinycloud_columns: number;
    canonical_key_column: boolean;
    canonical_key_index: boolean;
    app_preference_columns: number;
    app_preference_client_index: boolean;
    app_preference_status_check: boolean;
    app_preference_client_restrict: boolean;
    control_event_columns: number;
    control_event_index: boolean;
    signing_decision_columns: number;
    signing_decision_user_index: boolean;
    signing_decision_client_index: boolean;
    device_column_count: number;
    user_code_index: boolean;
    rate_index: boolean;
    expiry_index: boolean;
    user_foreign_key: boolean;
  }>>(`
    SELECT
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'user'
          AND column_name IN ('tinyCloudManageKeyEnabled', 'tinyCloudManageKeyMode', 'tinyCloudManageKeyPolicyEpoch')) AS user_tinycloud_columns,
      (SELECT COUNT(*) = 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'ethereum_keys' AND column_name = 'isCanonicalTinyCloud') AS canonical_key_column,
      to_regclass('public."ethereum_keys_one_active_canonical_tinycloud_key"') IS NOT NULL AS canonical_key_index,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_manage_key_app_preference') AS app_preference_columns,
      to_regclass('public."tinycloud_manage_key_app_preference_clientId_idx"') IS NOT NULL AS app_preference_client_index,
      EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tinycloud_manage_key_app_preference_status_check' AND contype = 'c') AS app_preference_status_check,
      EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tinycloud_manage_key_app_preference_clientId_fkey' AND confdeltype = 'r') AS app_preference_client_restrict,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_manage_key_control_event') AS control_event_columns,
      to_regclass('public."tinycloud_manage_key_control_event_userId_createdAt_idx"') IS NOT NULL AS control_event_index,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_manage_key_signing_decision') AS signing_decision_columns,
      to_regclass('public."tinycloud_manage_key_signing_decision_userId_createdAt_idx"') IS NOT NULL AS signing_decision_user_index,
      to_regclass('public."tinycloud_manage_key_signing_decision_userId_clientId_createdAt_idx"') IS NOT NULL AS signing_decision_client_index,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'device_authorization') AS device_column_count,
      to_regclass('public."device_authorization_userCode_key"') IS NOT NULL AS user_code_index,
      to_regclass('public."device_authorization_requestIpHash_requestedAt_idx"') IS NOT NULL AS rate_index,
      to_regclass('public."device_authorization_status_transactionExpiresAt_idx"') IS NOT NULL AS expiry_index,
      EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'device_authorization_approvedByUserId_fkey'
          AND contype = 'f'
      ) AS user_foreign_key
  `);
  const verified = physical[0];
  if (
    verified?.user_tinycloud_columns !== 3 ||
    !verified.canonical_key_column ||
    !verified.canonical_key_index ||
    verified.app_preference_columns !== 9 ||
    !verified.app_preference_client_index ||
    !verified.app_preference_status_check ||
    !verified.app_preference_client_restrict ||
    verified.control_event_columns !== 8 ||
    !verified.control_event_index ||
    verified.signing_decision_columns !== 8 ||
    !verified.signing_decision_user_index ||
    !verified.signing_decision_client_index ||
    verified?.device_column_count !== 21 ||
    !verified.user_code_index ||
    !verified.rate_index ||
    !verified.expiry_index ||
    !verified.user_foreign_key
  ) {
    throw new Error('TC-492 additive physical schema verification failed');
  }

  const destructiveRows = await database.$queryRawUnsafe<MigrationRow[]>(
    'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" WHERE migration_name = $1',
    tc488Migration,
  );
  if (destructiveRows[0]?.finished_at && !destructiveRows[0].rolled_back_at) {
    throw new Error(`${tc488Migration} was applied while recovering the additive schema`);
  }

  console.log(
    `Production additive migrations verified: ${[...tc492AdditiveMigrations.keys()].join(', ')}; ${deviceMigration}; ${tc488Migration} remains deliberately pending`,
  );
}

async function main() {
  requirePostgresUrl();
  await assertReviewedMigrationFiles();
  const database = createPrismaClient({ connectionString: process.env.DATABASE_URL });
  try {
    const state = await readState(database);
    const mode = selectProductionMigrationMode(state);
    if (mode === 'full') {
      runBunScript('scripts/assert-production-migration-ready.ts');
      runBunScript('db:migrate:apply');
      runBunScript('db:migrate:verify');
      return;
    }

    const successful = new Set(
      state.migrations
        .filter((row) => row.finished_at && !row.rolled_back_at)
        .map((row) => row.migration_name),
    );
    const pending = state.migrationDirectories.filter((name) => !successful.has(name));
    await deployAdditiveMigrationsBeforeTc488(database, pending);
  } finally {
    await database.$disconnect();
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
