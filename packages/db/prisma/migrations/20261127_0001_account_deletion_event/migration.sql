-- One row per deleted account: every address the account held (managed, archived and external keys) and the time of
-- the deletion. A consumer reads the rows in id order and keeps its own cursor. No email, no user id, no name, and no
-- foreign key to "user": the user row is gone when the row exists. Rows older than 60 days are deleted by the API.
-- A new table: no existing row is read or locked.
CREATE TABLE "account_deletion_event" (
    "id" BIGSERIAL NOT NULL,
    "addresses" TEXT[] NOT NULL,
    "deletedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "account_deletion_event_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "account_deletion_event_addresses_check" CHECK (cardinality("addresses") > 0)
);

CREATE INDEX "account_deletion_event_deletedAt_idx" ON "account_deletion_event"("deletedAt");
