-- Manual rollback for 20261127_0001_account_deletion_event (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
-- Every unread deletion event is lost; a consumer that has not read it never learns of that deletion.
DROP TABLE "account_deletion_event";
