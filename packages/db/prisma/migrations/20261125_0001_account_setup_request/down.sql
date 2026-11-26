-- Manual rollback for 20261125_0001_account_setup_request (Prisma does not run down files).
-- Roll back 20261125_0002_bootstrap_authority_account_setup first.
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
-- Every account setup request is lost; a setup in progress is not finished.
DROP TABLE "account_setup_request";
