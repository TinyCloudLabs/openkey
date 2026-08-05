#!/usr/bin/env bun

import { createPrismaClient } from '../packages/db/src/index';

const baselineCompletionMarker = '20260714_origin_main_schema_catchup';
const baselineCompletionChecksum =
  '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09';
const tc488Migration = '20260806_0002_remove_organization_key_custody';

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl?.match(/^postgres(ql)?:\/\//)) {
    throw new Error('Production migration preflight requires a PostgreSQL DATABASE_URL');
  }

  const prisma = createPrismaClient({ connectionString: databaseUrl });
  try {
    const migrations = await prisma.$queryRawUnsafe<Array<{
      migration_name: string;
      checksum: string;
      finished_at: Date | null;
      rolled_back_at: Date | null;
    }>>('SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations"');
    const baseline = migrations.find((row) => row.migration_name === baselineCompletionMarker);
    if (!baseline?.finished_at || baseline.rolled_back_at || baseline.checksum !== baselineCompletionChecksum) {
      throw new Error(`Production baseline marker ${baselineCompletionMarker} is missing or invalid`);
    }
    const failures = migrations.filter((row) => !row.finished_at && !row.rolled_back_at);
    if (failures.length) {
      throw new Error(`Production has unresolved failed migrations: ${failures.map((row) => row.migration_name).join(', ')}`);
    }

    const managedAccountTable = await prisma.$queryRaw<Array<{ exists: boolean }>>`
      SELECT to_regclass('public.managed_account') IS NOT NULL AS "exists"
    `;
    const tc488Applied = migrations.some(
      (row) => row.migration_name === tc488Migration && row.finished_at && !row.rolled_back_at,
    );
    if (managedAccountTable[0]?.exists || !tc488Applied) {
      throw new Error(
        'TC-488 is a destructive custody cutover. Automatic production migration is blocked until an operator verifies the managed-key disposition and applies the reviewed migration runbook.',
      );
    }
  } finally {
    await prisma.$disconnect();
  }

  console.log(`Production migration baseline and TC-488 cutover verified: ${baselineCompletionMarker}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
