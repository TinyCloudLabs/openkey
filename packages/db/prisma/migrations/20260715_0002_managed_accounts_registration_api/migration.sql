ALTER TABLE "organization" ADD COLUMN "brokerDid" TEXT;

ALTER TABLE "registration_intent"
  ADD COLUMN "createdByCredentialId" TEXT,
  ADD COLUMN "managedAccountId" TEXT;

-- Existing Phase-A rows are migration fixtures only. A production deployment
-- must populate the creator from its issuance audit log before this NOT NULL.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM "registration_intent") THEN
    RAISE EXCEPTION 'registration_intent creator backfill requires an explicit audit mapping';
  END IF;
END $$;

ALTER TABLE "registration_intent"
  ALTER COLUMN "createdByCredentialId" SET NOT NULL,
  ADD CONSTRAINT "registration_intent_credential_fkey"
    FOREIGN KEY ("createdByCredentialId") REFERENCES "organization_server_credential"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "registration_intent_account_fkey"
    FOREIGN KEY ("managedAccountId") REFERENCES "managed_account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE UNIQUE INDEX "registration_intent_managedAccountId_key"
  ON "registration_intent"("managedAccountId");

-- The credential used to create an intent must belong to the same tenant.
CREATE OR REPLACE FUNCTION openkey_registration_intent_tenant_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM "organization_server_credential" credential
    WHERE credential."id" = NEW."createdByCredentialId"
      AND credential."organizationId" = NEW."organizationId"
  ) THEN
    RAISE EXCEPTION 'registration intent credential belongs to another organization';
  END IF;

  IF NEW."managedAccountId" IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM "managed_account" account
    WHERE account."id" = NEW."managedAccountId"
      AND account."organizationId" = NEW."organizationId"
      AND account."externalUserId" = NEW."externalUserId"
  ) THEN
    RAISE EXCEPTION 'registration intent account belongs to another organization or subject';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER registration_intent_tenant_guard
  BEFORE INSERT OR UPDATE ON "registration_intent"
  FOR EACH ROW EXECUTE FUNCTION openkey_registration_intent_tenant_guard();
