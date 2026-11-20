-- TC-3569: the delegations a step-up has signed, kept until they expire so that
-- revoking the step-up can reach them on the node.
-- Additive: a new table and one trigger; no existing table or row changes, and
-- nothing writes it until the step-up endpoint ships.

CREATE TABLE "tinycloud_native_stepup_delegation" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "grantId" TEXT NOT NULL,
  "appId" TEXT NOT NULL,
  "delegationCid" TEXT NOT NULL,
  "tinycloudHost" TEXT NOT NULL,
  "address" TEXT NOT NULL,
  "siweDomain" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "revokeRequestedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "tinycloud_native_stepup_delegation_grantId_appId_fkey" FOREIGN KEY ("grantId", "appId")
    REFERENCES "tinycloud_native_stepup"("grantId", "appId") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "tinycloud_native_stepup_delegation_delegationCid_key" ON "tinycloud_native_stepup_delegation"("delegationCid");
CREATE INDEX "tinycloud_native_stepup_delegation_grantId_appId_idx" ON "tinycloud_native_stepup_delegation"("grantId", "appId");
CREATE INDEX "tinycloud_native_stepup_delegation_revokeRequestedAt_idx" ON "tinycloud_native_stepup_delegation"("revokeRequestedAt");

-- When a step-up becomes REVOKED, by any path (the app's revoke, the ceiling
-- removing the app, or its grant being revoked: the grant trigger revokes the
-- step-up, which fires this one), every delegation it signed that has not
-- expired is marked for the revoke sweep in the same transaction. The step-up
-- row is already locked by the triggering statement, so the lock order stays
-- grants, step-ups, then these rows.
CREATE FUNCTION tinycloud_native_stepup_revoked() RETURNS TRIGGER AS $$
BEGIN
  UPDATE "tinycloud_native_stepup_delegation"
    SET "revokeRequestedAt" = CURRENT_TIMESTAMP
    WHERE "grantId" = NEW."grantId" AND "appId" = NEW."appId"
      AND "revokeRequestedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tinycloud_native_stepup_revoked
  AFTER UPDATE OF "status" ON "tinycloud_native_stepup" FOR EACH ROW
  WHEN (NEW."status" = 'REVOKED' AND OLD."status" IS DISTINCT FROM 'REVOKED')
  EXECUTE FUNCTION tinycloud_native_stepup_revoked();
