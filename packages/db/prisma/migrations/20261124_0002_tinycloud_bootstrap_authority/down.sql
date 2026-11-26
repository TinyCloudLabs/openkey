-- Manual rollback for 20261124_0002_tinycloud_bootstrap_authority (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
-- The stored authority values are lost.
ALTER TABLE "tinycloud_bootstrap_state" DROP CONSTRAINT "tinycloud_bootstrap_state_authority_check";
ALTER TABLE "tinycloud_bootstrap_state" DROP COLUMN "authority";
