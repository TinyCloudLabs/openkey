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

-- A revoke sticks. The AFTER trigger above revokes the step-ups of a grant that
-- is already revoked; this BEFORE trigger closes the other direction. An ACTIVE
-- step-up is refused (TC773) when the grant is not ACTIVE, and a step-up that a
-- grant revocation took down never becomes ACTIVE again. The grant row is
-- locked FOR SHARE, so an approval racing sign-out, an Apple revoke or a
-- consent withdrawal either commits first and is then revoked by the AFTER
-- trigger, or waits for the revocation and is refused. Same style as
-- tinycloud_native_assert_grant_live.
CREATE FUNCTION tinycloud_native_stepup_guard() RETURNS TRIGGER AS $$
DECLARE
  grant_status TEXT;
BEGIN
  IF NEW."status" <> 'ACTIVE' THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD."revokedReason" = 'grant_revoked' THEN
    RAISE EXCEPTION 'tinycloud native step-up was revoked with its grant' USING ERRCODE = 'TC773';
  END IF;
  PERFORM set_config('lock_timeout', '5s', true);
  SELECT g."status" INTO grant_status FROM "tinycloud_native_grant" g WHERE g."id" = NEW."grantId" FOR SHARE;
  IF NOT FOUND OR grant_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'tinycloud native grant is no longer active' USING ERRCODE = 'TC773';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tinycloud_native_stepup_guard
  BEFORE INSERT OR UPDATE OF "status" ON "tinycloud_native_stepup" FOR EACH ROW
  EXECUTE FUNCTION tinycloud_native_stepup_guard();
