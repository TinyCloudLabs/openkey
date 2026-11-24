-- Manual rollback for 20261121_0004_native_stepup_delegation (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
-- Delegations still marked for revocation are forgotten: drain the revoke sweep first.
DROP TRIGGER IF EXISTS tinycloud_native_stepup_revoked ON "tinycloud_native_stepup";
DROP FUNCTION IF EXISTS tinycloud_native_stepup_revoked();
DROP TABLE IF EXISTS "tinycloud_native_stepup_delegation";
