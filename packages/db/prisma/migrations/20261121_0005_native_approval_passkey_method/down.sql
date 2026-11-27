-- Manual rollback for 20261121_0005_native_approval_passkey_method (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
-- The audit column's values are lost.
ALTER TABLE "tinycloud_native_request"
  DROP CONSTRAINT IF EXISTS "tinycloud_native_request_approvalPasskeyMethod_check",
  DROP COLUMN IF EXISTS "approvalPasskeyMethod";
