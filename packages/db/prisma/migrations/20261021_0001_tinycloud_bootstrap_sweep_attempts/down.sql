-- Manual rollback for 20261021_0001_tinycloud_bootstrap_sweep_attempts (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
ALTER TABLE "tinycloud_bootstrap_state" DROP COLUMN IF EXISTS "sweepAttempts";
