ALTER TABLE "tinycloud_native_request"
  ADD COLUMN "renewalAsk" JSONB,
  ADD COLUMN "renewalLeaseCid" TEXT;
ALTER TABLE "tinycloud_native_preparation" ADD COLUMN "renewalChoice" JSONB;
ALTER TABLE "tinycloud_native_grant" ADD COLUMN "renewalLeaseCid" TEXT;

CREATE TABLE "native_renewal_lease" (
  "leaseCid" TEXT PRIMARY KEY REFERENCES "renewal_lease"("leaseCid") ON DELETE CASCADE ON UPDATE CASCADE,
  "requestId" TEXT NOT NULL,
  "grantId" TEXT,
  "deliveredAt" TIMESTAMP(3),
  "revokeUntil" TIMESTAMP(3) NOT NULL,
  "stopRequested" BOOLEAN NOT NULL DEFAULT FALSE,
  "originalRevokedAt" TIMESTAMP(3)
);
CREATE UNIQUE INDEX "native_renewal_lease_grantId_key" ON "native_renewal_lease" ("grantId");
CREATE INDEX "native_renewal_lease_requestId_idx" ON "native_renewal_lease" ("requestId");
CREATE INDEX "native_renewal_lease_stop_pending_idx" ON "native_renewal_lease" ("revokeUntil")
  WHERE "stopRequested";

-- Carry all grant withdrawal paths, including SQL consent withdrawal, into the owner lease ledger.
-- The ledger outlives the native rows so retries do not depend on the OAuth token table.
CREATE FUNCTION queue_native_lease_stop() RETURNS TRIGGER AS $$
BEGIN
  IF TG_TABLE_NAME = 'tinycloud_native_grant' THEN
    UPDATE "native_renewal_lease" SET "stopRequested" = TRUE WHERE "grantId" = OLD.id;
  ELSE
    UPDATE "native_renewal_lease" SET "stopRequested" = TRUE
      WHERE "requestId" = OLD.id AND "grantId" IS NULL;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER native_grant_queue_lease_stop
  AFTER UPDATE OF "status" ON "tinycloud_native_grant"
  FOR EACH ROW WHEN (OLD."status" IS DISTINCT FROM NEW."status" AND NEW."status" = 'REVOKED')
  EXECUTE FUNCTION queue_native_lease_stop();
CREATE TRIGGER native_grant_delete_queue_lease_stop
  AFTER DELETE ON "tinycloud_native_grant"
  FOR EACH ROW EXECUTE FUNCTION queue_native_lease_stop();
CREATE TRIGGER native_request_queue_lease_stop
  AFTER UPDATE OF "status" ON "tinycloud_native_request"
  FOR EACH ROW WHEN (OLD."status" IS DISTINCT FROM NEW."status" AND NEW."status" = 'WITHDRAWN')
  EXECUTE FUNCTION queue_native_lease_stop();
CREATE TRIGGER native_request_delete_queue_lease_stop
  AFTER DELETE ON "tinycloud_native_request"
  FOR EACH ROW EXECUTE FUNCTION queue_native_lease_stop();
