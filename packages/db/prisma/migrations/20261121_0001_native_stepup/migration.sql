-- TC-3569: step-ups on a native TinyCloud grant (TinyCloud One framed apps).
-- Additive: a new table and one trigger; no existing table or row changes, and
-- nothing writes it until the step-up endpoint ships.

CREATE TABLE "tinycloud_native_stepup" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "grantId" TEXT NOT NULL,
  "appId" TEXT NOT NULL,
  "approvedPermissions" JSONB NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'ACTIVE',
  "approvedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "revokedAt" TIMESTAMP(3),
  "revokedReason" TEXT,
  "lastRenewedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "tinycloud_native_stepup_grantId_fkey" FOREIGN KEY ("grantId") REFERENCES "tinycloud_native_grant"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "tinycloud_native_stepup_grantId_appId_key" ON "tinycloud_native_stepup"("grantId", "appId");

-- A closed set: an unknown status can never satisfy a renewal predicate.
ALTER TABLE "tinycloud_native_stepup" ADD CONSTRAINT "tinycloud_native_stepup_status_check"
  CHECK ("status" IN ('ACTIVE', 'REVOKED'));

-- A step-up never outlives its grant. Revoking a grant, by sign-out, consent
-- withdrawal or direct SQL, revokes its step-ups in the same transaction. The
-- grant row is already locked by the triggering statement, so this keeps the
-- global lock order: consent, generation, requests, grants, step-ups, then
-- token rows.
CREATE FUNCTION tinycloud_native_stepup_grant_revoked() RETURNS TRIGGER AS $$
BEGIN
  UPDATE "tinycloud_native_stepup"
    SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP, "revokedReason" = 'grant_revoked'
    WHERE "grantId" = NEW."id" AND "status" <> 'REVOKED';
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tinycloud_native_stepup_grant_revoked
  AFTER UPDATE OF "status" ON "tinycloud_native_grant" FOR EACH ROW
  WHEN (NEW."status" = 'REVOKED' AND OLD."status" IS DISTINCT FROM 'REVOKED')
  EXECUTE FUNCTION tinycloud_native_stepup_grant_revoked();
