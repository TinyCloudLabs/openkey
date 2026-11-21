-- Manual rollback for 20261121_0001_native_stepup (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
-- Drop the grant trigger first: left in place without its table, it would make
-- every grant revocation fail and leave grants ACTIVE.
DROP TRIGGER IF EXISTS tinycloud_native_stepup_grant_revoked ON "tinycloud_native_grant";
DROP FUNCTION IF EXISTS tinycloud_native_stepup_grant_revoked();
DROP TRIGGER IF EXISTS tinycloud_native_stepup_guard ON "tinycloud_native_stepup";
DROP FUNCTION IF EXISTS tinycloud_native_stepup_guard();
DROP TABLE IF EXISTS "tinycloud_native_stepup";
