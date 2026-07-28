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

    const managedAccountTable = await prisma.$queryRaw<
      Array<{ exists: boolean }>
    >`
      SELECT to_regclass('public.managed_account') IS NOT NULL AS "exists"
    `;

    // Legacy origin/main PostgreSQL does not have managed_account until the
    // pending managed-account migrations run. Keep every data check when the
    // table is present, but do not make the preflight itself require it.
    if (managedAccountTable[0]?.exists) {
      // Use the same explicit ASCII whitespace set as normalizeSubjectEmail()'s trimAscii():
      // \t \n \r \x0c (form feed) \x0b (vertical tab) and space.
      // btrim without explicit characters only trims spaces and would miss other whitespace,
      // allowing whitespace-only emails to pass preflight and then abort migration 20260720_0001.
      const missingOwnerEmails = await prisma.$queryRaw<
        Array<{
          id: string;
          organizationId: string;
          ownerUserId: string;
        }>
      >`
      SELECT ma."id", ma."organizationId", ma."ownerUserId"
      FROM "managed_account" ma
      LEFT JOIN "user" u ON u.id = ma."ownerUserId"
      WHERE ma."ownerUserId" IS NOT NULL
        AND (u."email" IS NULL OR btrim(u."email", E'\t\n\r\x0c\x0b ') = '')
      `;
      if (missingOwnerEmails.length > 0) {
        throw new Error(
          `Production has managed accounts with missing owner emails: ${missingOwnerEmails.map((row) => row.id).join(", ")}`,
        );
      }

      // Enforce the full normalizeSubjectEmail() predicate on every owner email that
      // would be backfilled into subjectEmail. The migration backfill uses
      // lower(btrim(email, whitespace)) but does NOT check ASCII-only, length ≤ 254,
      // or @ placement. An email that passes the migration's NULL/empty guard but
      // fails these checks will be stored silently and then fail at runtime.
      //
      // Matches the exact normalizeSubjectEmail() predicate (tenant-managed-accounts.ts):
      //   trimAscii → lower → length ≤ 254 → ASCII-only → has @ → not starts/ends with @
      const invalidOwnerEmailRows = await prisma.$queryRaw<
        Array<{
          id: string;
          organizationId: string;
          ownerUserId: string;
          reason: string;
        }>
      >`
      SELECT
        ma."id",
        ma."organizationId",
        ma."ownerUserId",
        CASE
          WHEN octet_length(u."email") > char_length(u."email")
            THEN 'non-ASCII characters'
          WHEN char_length(lower(btrim(u."email", E'\t\n\r\x0c\x0b '))) > 254
            THEN 'exceeds 254 characters after normalization'
          WHEN lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) NOT LIKE '%@%'
            THEN 'missing @ symbol'
          WHEN lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) LIKE '@%'
            THEN 'starts with @'
          WHEN lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) LIKE '%@'
            THEN 'ends with @'
          ELSE 'unknown'
        END AS reason
      FROM "managed_account" ma
      JOIN "user" u ON u.id = ma."ownerUserId"
      WHERE ma."ownerUserId" IS NOT NULL
        AND (
          octet_length(u."email") > char_length(u."email")
          OR char_length(lower(btrim(u."email", E'\t\n\r\x0c\x0b '))) > 254
          OR lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) NOT LIKE '%@%'
          OR lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) LIKE '@%'
          OR lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) LIKE '%@'
        )
      `;
      if (invalidOwnerEmailRows.length > 0) {
        const details = invalidOwnerEmailRows
          .map((row) => `${row.id} (${row.reason})`)
          .join(", ");
        throw new Error(
          `Production has managed accounts whose owner emails would fail normalizeSubjectEmail() validation: ${details}. ` +
            "These accounts cannot be migrated safely; correct the owner email addresses before deploying.",
        );
      }

      const ownershipMismatches = await prisma.$queryRaw<
        Array<{
          id: string;
          organizationId: string;
        }>
      >`
      SELECT ma."id", ma."organizationId"
      FROM "managed_account" ma
      LEFT JOIN "ethereum_keys" ek ON ek."id" = ma."keyId"
      WHERE (ma."ownerUserId" IS NULL AND ek."userId" IS NOT NULL)
         OR (ma."ownerUserId" IS NOT NULL AND ek."userId" IS DISTINCT FROM ma."ownerUserId")
      `;
      if (ownershipMismatches.length > 0) {
        throw new Error(
          `Production has managed-account ownership mismatches that cannot be migrated safely: ${ownershipMismatches.map((row) => row.id).join(", ")}`,
        );
      }

      // Feature-detect whether subjectEmail has already been added by a prior (partial)
      // run of the migration. The canonical-collision check expression differs between
      // the pre-migration schema (ownerUserId NOT NULL, no subjectEmail column) and the
      // post-migration schema (subjectEmail NOT NULL, ownerUserId nullable).
      const subjectEmailColumn = await prisma.$queryRaw<
        Array<{ exists: boolean }>
      >`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'managed_account'
          AND column_name = 'subjectEmail'
      ) AS "exists"
      `;
      const hasSubjectEmail = subjectEmailColumn[0]?.exists ?? false;

      // Use the same explicit ASCII whitespace set as normalizeSubjectEmail()'s trimAscii():
      // \t \n \r \x0c (form feed) \x0b (vertical tab) and space.
      // btrim without explicit characters only trims spaces and would miss other whitespace.
      const canonicalCollisions = hasSubjectEmail
        ? await prisma.$queryRaw<
            Array<{
              organizationId: string;
              canonicalEmail: string;
              accountCount: bigint;
            }>
          >`
          SELECT *
          FROM (
            SELECT
              ma."organizationId",
              lower(btrim(COALESCE(u."email", ma."subjectEmail"), E'\t\n\r\x0c\x0b ')) AS "canonicalEmail",
              count(*)::bigint AS "accountCount"
            FROM "managed_account" ma
            LEFT JOIN "user" u ON u.id = ma."ownerUserId"
            GROUP BY ma."organizationId", lower(btrim(COALESCE(u."email", ma."subjectEmail"), E'\t\n\r\x0c\x0b '))
          ) scoped
          WHERE "accountCount" > 1
        `
        : await prisma.$queryRaw<
            Array<{
              organizationId: string;
              canonicalEmail: string;
              accountCount: bigint;
            }>
          >`
          SELECT *
          FROM (
            SELECT
              ma."organizationId",
              lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) AS "canonicalEmail",
              count(*)::bigint AS "accountCount"
            FROM "managed_account" ma
            JOIN "user" u ON u.id = ma."ownerUserId"
            GROUP BY ma."organizationId", lower(btrim(u."email", E'\t\n\r\x0c\x0b '))
          ) scoped
          WHERE "accountCount" > 1
        `;
      if (canonicalCollisions.length > 0) {
        throw new Error(
          `Production has canonical managed-account email collisions: ${canonicalCollisions.map((row) => `${row.organizationId}:${row.canonicalEmail}`).join(", ")}`,
        );
      }
    }

    const registrationIntentTable = await prisma.$queryRaw<
      Array<{ exists: boolean }>
    >`
      SELECT to_regclass('public.registration_intent') IS NOT NULL AS "exists"
    `;
    if (registrationIntentTable[0]?.exists) {
      const pendingRegistrationIntents = await prisma.$queryRaw<
        Array<{ id: string }>
      >`
        SELECT "id"
        FROM "registration_intent"
        WHERE "status" = 'PENDING'
        LIMIT 1
      `;
      if (pendingRegistrationIntents.length > 0) {
        throw new Error(
          "Production has pending registration-intent rows that cannot be migrated safely; clear or consume them before deploying",
        );
      }
    }
  } finally {
    await prisma.$disconnect();
  }

  console.log(
    `Production migration baseline marker verified: ${baselineCompletionMarker}`,
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
