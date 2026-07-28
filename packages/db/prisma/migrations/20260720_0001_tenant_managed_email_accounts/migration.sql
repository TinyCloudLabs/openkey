-- Tenant-managed email accounts and management credential migration.

-- CreateEnum
CREATE TYPE "OauthClientMode" AS ENUM ('PERSONAL', 'TENANT_MANAGED');

-- AlterEnum
ALTER TYPE "ManagedAccountState" ADD VALUE 'DISABLED';

-- AlterEnum
ALTER TYPE "OrganizationCredentialKind" ADD VALUE 'MANAGEMENT';

-- DropForeignKey
ALTER TABLE "ethereum_keys" DROP CONSTRAINT "ethereum_keys_userId_fkey";

-- DropForeignKey
ALTER TABLE "managed_account" DROP CONSTRAINT "managed_account_key_owner_fkey";

-- DropForeignKey
ALTER TABLE "managed_account" DROP CONSTRAINT "managed_account_owner_fkey";

-- DropIndex
DROP INDEX "managed_account_key_owner_key";

-- AlterTable
ALTER TABLE "ethereum_keys" ALTER COLUMN "userId" DROP NOT NULL;

-- AlterTable: add new columns as nullable so existing rows are not blocked
ALTER TABLE "managed_account" ADD COLUMN     "metadata" JSONB,
ADD COLUMN     "subjectEmail" TEXT,
ALTER COLUMN "ownerUserId" DROP NOT NULL,
ALTER COLUMN "externalUserId" DROP NOT NULL,
ALTER COLUMN "policyTemplate" SET DEFAULT 'tenant-full-signing-v1';

-- Backfill: derive subjectEmail from the owner user's email for legacy rows.
-- btrim with the full ASCII whitespace set matches normalizeSubjectEmail()'s trimAscii().
-- The explicit character set trims \t \n \r \x0c (form feed) \x0b (vertical tab) and space,
-- matching JavaScript's /^[\t\n\r\f\v ]+|[\t\n\r\f\v ]+$/ pattern.
UPDATE "managed_account" ma
SET "subjectEmail" = lower(btrim(u.email, E'\t\n\r\x0c\x0b '))
FROM "user" u
WHERE u.id = ma."ownerUserId"
  AND ma."subjectEmail" IS NULL;

-- Safety check: reject the migration if any row still lacks an email.
-- This fires before SET NOT NULL so the DBA sees a clear message.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM "managed_account" WHERE "subjectEmail" IS NULL OR btrim("subjectEmail", E'\t\n\r\x0c\x0b ') = ''
  ) THEN
    RAISE EXCEPTION
      'Migration 20260720_0001 aborted: managed_account rows exist with a NULL or empty subjectEmail after backfill. '
      'Run the production preflight check (assert-production-migration-ready) to identify the affected rows.';
  END IF;
END
$$;

-- Safety check: reject the migration on canonical email collisions.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM (
      SELECT "organizationId", lower(btrim("subjectEmail", E'\t\n\r\x0c\x0b ')) AS email, count(*) AS n
      FROM "managed_account"
      GROUP BY "organizationId", lower(btrim("subjectEmail", E'\t\n\r\x0c\x0b '))
    ) t
    WHERE n > 1
  ) THEN
    RAISE EXCEPTION
      'Migration 20260720_0001 aborted: managed_account has duplicate (organizationId, subjectEmail) pairs. '
      'Run the production preflight check (assert-production-migration-ready) to identify the collisions.';
  END IF;
END
$$;

-- Now it is safe to enforce the constraint.
ALTER TABLE "managed_account" ALTER COLUMN "subjectEmail" SET NOT NULL;

-- AlterTable
ALTER TABLE "oauth_client" ADD COLUMN     "mode" "OauthClientMode" NOT NULL DEFAULT 'PERSONAL';

-- Backfill: ALL organization-scoped OAuth clients must be migrated to mode=TENANT_MANAGED.
-- Legacy clients were created with organizationId but without the openkeyClientMode metadata
-- field; they default to PERSONAL, select personal keys, and are excluded from tenant
-- disable/eject token revocation.  Every client bound to an organization is definitionally
-- tenant-managed, so we set mode=TENANT_MANAGED unconditionally for them and populate the
-- canonical metadata (openkeyClientMode + openkeyOrganizationId) so downstream code that
-- inspects metadata still works.  The openkeyOrganizationId field is required for userinfo
-- and id-token key-claims routing to identify which organization's managed accounts apply.
UPDATE "oauth_client"
SET "mode" = 'TENANT_MANAGED',
    "metadata" = COALESCE("metadata", '{}'::jsonb)
                   || jsonb_build_object(
                       'openkeyClientMode', 'TENANT_MANAGED',
                       'openkeyOrganizationId', "organizationId"
                     )
WHERE "organizationId" IS NOT NULL
  AND "mode" = 'PERSONAL';

-- CreateTable
CREATE TABLE "managed_account_operation" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "managedAccountId" TEXT,
    "credentialId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "requestHash" TEXT NOT NULL,
    "response" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "managed_account_operation_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "managed_account_operation_org_created_idx" ON "managed_account_operation"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "managed_account_operation_account_created_idx" ON "managed_account_operation"("managedAccountId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "managed_account_operation_idempotency_key" ON "managed_account_operation"("organizationId", "action", "idempotencyKey");

-- CreateIndex: must come after NOT NULL is enforced and backfill is complete.
CREATE UNIQUE INDEX "managed_account_org_subject_email_key" ON "managed_account"("organizationId", "subjectEmail");

-- AddForeignKey
ALTER TABLE "ethereum_keys" ADD CONSTRAINT "ethereum_keys_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "managed_account" ADD CONSTRAINT "managed_account_owner_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "managed_account" ADD CONSTRAINT "managed_account_key_fkey" FOREIGN KEY ("keyId") REFERENCES "ethereum_keys"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "managed_account_operation" ADD CONSTRAINT "managed_account_operation_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "managed_account_operation" ADD CONSTRAINT "managed_account_operation_account_fkey" FOREIGN KEY ("managedAccountId") REFERENCES "managed_account"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "managed_account_operation" ADD CONSTRAINT "managed_account_operation_credential_fkey" FOREIGN KEY ("credentialId") REFERENCES "organization_server_credential"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
