#!/usr/bin/env bun

import { createHash } from 'node:crypto';
import { createPrismaClient } from '../packages/db/src/index';

type QueryClient = {
  $queryRawUnsafe<T>(query: string): Promise<T>;
};

type SelectionRow = {
  userId: string;
  candidateKeyId: string | null;
  candidateAddress: string | null;
  canonicalKeyId: string | null;
  canonicalAddress: string | null;
};

export type CanonicalCutoverReport = {
  schema: 'openkey.tc492.canonical-cutover-report.v1';
  phase: 'pre-expand' | 'expanded';
  eligibleUserCount: number;
  deterministicCandidateCount: number;
  existingCanonicalCount: number;
  unassignedCandidateCount: number;
  selectionConflictCount: number;
  predictedAddressChangeCount: number;
  canonicalWithoutEligibleKeyCount: number;
  tenantCustodyKeyCount: number;
  candidateDigestSha256: string;
};

function selectionSql(hasCanonicalColumn: boolean, hasPurposeColumn: boolean): string {
  const personalKeyFilter = hasPurposeColumn ? `AND "keyPurpose" = 'PERSONAL'` : '';
  const canonical = hasCanonicalColumn
    ? `SELECT "userId", "id", "address"
       FROM "ethereum_keys"
       WHERE "userId" IS NOT NULL AND "isCanonicalTinyCloud" = true`
    : `SELECT NULL::text AS "userId", NULL::text AS "id", NULL::text AS "address" WHERE false`;
  return `
    WITH ranked AS (
      SELECT "userId", "id", "address", row_number() OVER (
        PARTITION BY "userId"
        ORDER BY "keyIndex" ASC, "createdAt" ASC, "id" ASC
      ) AS position
      FROM "ethereum_keys"
      WHERE "userId" IS NOT NULL
        AND "keyType" = 'MANAGED'
        AND "archivedAt" IS NULL
        ${personalKeyFilter}
    ), candidates AS (
      SELECT "userId", "id", "address" FROM ranked WHERE position = 1
    ), canonical AS (${canonical})
    SELECT
      COALESCE(candidates."userId", canonical."userId") AS "userId",
      candidates."id" AS "candidateKeyId",
      candidates."address" AS "candidateAddress",
      canonical."id" AS "canonicalKeyId",
      canonical."address" AS "canonicalAddress"
    FROM candidates
    FULL OUTER JOIN canonical USING ("userId")
    ORDER BY COALESCE(candidates."userId", canonical."userId") ASC
  `;
}

export function summarizeCanonicalCutover(
  rows: SelectionRow[],
  phase: CanonicalCutoverReport['phase'],
  tenantCustodyKeyCount: number,
): CanonicalCutoverReport {
  const candidates = rows.filter((row) => row.candidateKeyId && row.candidateAddress);
  const canonicals = rows.filter((row) => row.canonicalKeyId && row.canonicalAddress);
  const digest = createHash('sha256');
  for (const row of candidates) {
    digest.update(`${row.userId}\0${row.candidateKeyId}\0${row.candidateAddress}\n`);
  }
  return {
    schema: 'openkey.tc492.canonical-cutover-report.v1',
    phase,
    eligibleUserCount: candidates.length,
    deterministicCandidateCount: candidates.length,
    existingCanonicalCount: canonicals.length,
    unassignedCandidateCount: rows.filter((row) => row.candidateKeyId && !row.canonicalKeyId).length,
    selectionConflictCount: rows.filter((row) => (
      row.candidateKeyId && row.canonicalKeyId && row.candidateKeyId !== row.canonicalKeyId
    )).length,
    predictedAddressChangeCount: rows.filter((row) => (
      row.candidateAddress && row.canonicalAddress && row.candidateAddress !== row.canonicalAddress
    )).length,
    canonicalWithoutEligibleKeyCount: rows.filter((row) => row.canonicalKeyId && !row.candidateKeyId).length,
    tenantCustodyKeyCount,
    candidateDigestSha256: digest.digest('hex'),
  };
}

export async function buildCanonicalCutoverReport(
  database: QueryClient,
): Promise<CanonicalCutoverReport> {
  const columns = await database.$queryRawUnsafe<Array<{ column_name: string }>>(`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'ethereum_keys'
      AND column_name IN ('isCanonicalTinyCloud', 'keyPurpose')
  `);
  const names = new Set(columns.map((row) => row.column_name));
  const hasCanonicalColumn = names.has('isCanonicalTinyCloud');
  const hasPurposeColumn = names.has('keyPurpose');
  const rows = await database.$queryRawUnsafe<SelectionRow[]>(
    selectionSql(hasCanonicalColumn, hasPurposeColumn),
  );
  let tenantCustodyKeyCount = 0;
  if (hasPurposeColumn) {
    const count = await database.$queryRawUnsafe<Array<{ count: number }>>(`
      SELECT COUNT(*)::int AS count
      FROM "ethereum_keys"
      WHERE "keyPurpose" = 'MANAGED_ACCOUNT'
    `);
    tenantCustodyKeyCount = count[0]?.count ?? 0;
  }
  return summarizeCanonicalCutover(
    rows,
    hasCanonicalColumn ? 'expanded' : 'pre-expand',
    tenantCustodyKeyCount,
  );
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl?.match(/^postgres(ql)?:\/\//)) {
    throw new Error('TC-492 cutover report requires a PostgreSQL DATABASE_URL');
  }
  const prisma = createPrismaClient({ connectionString: databaseUrl });
  try {
    console.log(JSON.stringify(await buildCanonicalCutoverReport(prisma), null, 2));
  } finally {
    await prisma.$disconnect();
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
