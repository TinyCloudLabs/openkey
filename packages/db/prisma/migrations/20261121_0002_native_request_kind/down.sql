-- Manual rollback for 20261121_0002_native_request_kind (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
-- Step-up requests have no meaning without the columns; delete them first.
DELETE FROM "tinycloud_native_request" WHERE "kind" = 'STEPUP';
DROP INDEX IF EXISTS "tinycloud_native_request_grantId_idx";
ALTER TABLE "tinycloud_native_request"
  DROP CONSTRAINT IF EXISTS "tinycloud_native_request_grantId_fkey",
  DROP CONSTRAINT IF EXISTS "tinycloud_native_request_kind_check",
  DROP COLUMN IF EXISTS "appId",
  DROP COLUMN IF EXISTS "grantId",
  DROP COLUMN IF EXISTS "kind";
