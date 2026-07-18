#!/usr/bin/env bun

import { createPrismaClient } from '../packages/db/src/index';

const baselineCompletionMarker = '20260714_origin_main_schema_catchup';
const baselineCompletionChecksum =
  '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09';

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error('DATABASE_URL must be set');
  }
  if (
    !databaseUrl.startsWith('postgresql://') &&
    !databaseUrl.startsWith('postgres://')
  ) {
    throw new Error('Production migration preflight requires PostgreSQL');
  }

  const prisma = createPrismaClient({ connectionString: databaseUrl });
  try {
    const table = await prisma.$queryRaw<Array<{ exists: boolean }>>`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = '_prisma_migrations'
      ) AS "exists"
    `;
    if (!table[0]?.exists) {
      throw new Error(
        'Production migration history is absent; run the protected baseline workflow first'
      );
    }

    const rows = await prisma.$queryRawUnsafe<
      Array<{
        migration_name: string;
        checksum: string;
        finished_at: Date | null;
        rolled_back_at: Date | null;
      }>
    >(
      'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations"'
    );
    const activeFailures = rows.filter(
      (row) => !row.finished_at && !row.rolled_back_at
    );
    if (activeFailures.length > 0) {
      throw new Error(
        `Production has unresolved failed migrations: ${activeFailures
          .map((row) => row.migration_name)
          .join(', ')}. Run the protected baseline recovery workflow first`
      );
    }
    const markerRows = rows.filter(
      (row) => row.migration_name === baselineCompletionMarker
    );
    if (markerRows.length === 0) {
      throw new Error(
        `Production baseline marker ${baselineCompletionMarker} is absent; run the protected baseline workflow first`
      );
    }
    const marker = markerRows.some(
      (row) =>
        row.checksum === baselineCompletionChecksum &&
        row.finished_at &&
        !row.rolled_back_at
    );
    if (!marker) {
      throw new Error(
        `Production baseline marker ${baselineCompletionMarker} has an invalid checksum or status; refusing to deploy`
      );
    }
  } finally {
    await prisma.$disconnect();
  }

  console.log(
    `Production migration baseline marker verified: ${baselineCompletionMarker}`
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
