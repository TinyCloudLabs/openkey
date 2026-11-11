ALTER TABLE reviewer_account
  ADD COLUMN "seedRun" JSONB,
  ADD COLUMN "seedStartedAt" TIMESTAMP(3),
  ADD COLUMN "writerExpiresAt" TIMESTAMP(3);

CREATE TABLE reviewer_cleanup (
  id TEXT PRIMARY KEY,
  store TEXT NOT NULL,
  "ownerUserId" TEXT NOT NULL,
  address TEXT NOT NULL,
  "spaceId" TEXT NOT NULL UNIQUE,
  "nodeHost" TEXT NOT NULL,
  "sealedBlob" TEXT,
  "sealingContext" TEXT,
  "retiredAt" TIMESTAMP(3) NOT NULL,
  "tombstoneUntil" TIMESTAMP(3) NOT NULL,
  "boundExceeded" BOOLEAN NOT NULL DEFAULT false,
  "initialWipedAt" TIMESTAMP(3),
  "completedAt" TIMESTAMP(3),
  "retryAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "leaseUntil" TIMESTAMP(3),
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX reviewer_cleanup_due ON reviewer_cleanup ("retryAt", "completedAt");

ALTER TABLE tinycloud_native_request
  ADD COLUMN "reviewerEpoch" INTEGER,
  ADD COLUMN "reviewerSessionId" TEXT,
  ADD COLUMN "reviewerDeadline" TIMESTAMP(3);
CREATE TRIGGER native_request_reviewer_epoch BEFORE INSERT OR UPDATE ON tinycloud_native_request
  FOR EACH ROW EXECUTE FUNCTION check_reviewer_epoch();
