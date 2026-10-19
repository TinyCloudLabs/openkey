-- Manual rollback for 20261019_0001_app_sign_in_day (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
DROP TABLE IF EXISTS "app_sign_in_day";
