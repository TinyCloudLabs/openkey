import { afterAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { buildCanonicalCutoverReport } from './report-tc-492-canonical-cutover';

const database = new PGlite();
await database.exec(`
  CREATE TYPE "KeyType" AS ENUM ('MANAGED', 'EXTERNAL');
  CREATE TYPE "KeyPurpose" AS ENUM ('PERSONAL', 'MANAGED_ACCOUNT');
  CREATE TABLE "ethereum_keys" (
    "id" text PRIMARY KEY,
    "userId" text,
    "address" text NOT NULL,
    "keyType" "KeyType" NOT NULL,
    "keyPurpose" "KeyPurpose" NOT NULL,
    "isCanonicalTinyCloud" boolean NOT NULL DEFAULT false,
    "keyIndex" integer NOT NULL DEFAULT 0,
    "archivedAt" timestamp,
    "createdAt" timestamp NOT NULL
  );
  INSERT INTO "ethereum_keys" VALUES
    ('key-b', 'user-1', '0x2222222222222222222222222222222222222222', 'MANAGED', 'PERSONAL', false, 0, NULL, '2026-01-01'),
    ('key-a', 'user-1', '0x1111111111111111111111111111111111111111', 'MANAGED', 'PERSONAL', true, 0, NULL, '2026-01-01'),
    ('tenant', 'user-1', '0x3333333333333333333333333333333333333333', 'MANAGED', 'MANAGED_ACCOUNT', false, 0, NULL, '2025-01-01'),
    ('external', 'user-2', '0x4444444444444444444444444444444444444444', 'EXTERNAL', 'PERSONAL', false, 0, NULL, '2025-01-01'),
    ('key-c', 'user-3', '0x5555555555555555555555555555555555555555', 'MANAGED', 'PERSONAL', false, 2, NULL, '2026-01-01');
`);

const queryClient = {
  $queryRawUnsafe: async <T>(query: string) => (await database.query(query)).rows as T,
};

afterAll(() => database.close());

describe('TC-492 canonical cutover dry-run report', () => {
  test('selects deterministically, excludes tenant custody, and reports no address changes', async () => {
    const first = await buildCanonicalCutoverReport(queryClient);
    const second = await buildCanonicalCutoverReport(queryClient);
    expect(first).toEqual(second);
    expect(first).toMatchObject({
      phase: 'expanded',
      eligibleUserCount: 2,
      deterministicCandidateCount: 2,
      existingCanonicalCount: 1,
      unassignedCandidateCount: 1,
      selectionConflictCount: 0,
      predictedAddressChangeCount: 0,
      canonicalWithoutEligibleKeyCount: 0,
      tenantCustodyKeyCount: 1,
    });
    expect(first.candidateDigestSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  test('fails the release invariant visibly if another key is marked canonical', async () => {
    await database.exec(`
      UPDATE "ethereum_keys" SET "isCanonicalTinyCloud" = false WHERE "userId" = 'user-1';
      UPDATE "ethereum_keys" SET "isCanonicalTinyCloud" = true WHERE "id" = 'key-b';
    `);
    const report = await buildCanonicalCutoverReport(queryClient);
    expect(report.selectionConflictCount).toBe(1);
    expect(report.predictedAddressChangeCount).toBe(1);
  });
});
