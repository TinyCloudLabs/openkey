-- Drop RegistrationIntent: the registration flow has been removed.
-- The service and hosted page were deleted in a prior commit; this migration
-- drops the legacy table and enum after the production preflight confirms no
-- pending rows remain. Any row with status='PENDING' is evidence of data drift
-- and must be resolved by the operator before proceeding.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM "registration_intent" WHERE "status" = 'PENDING'
  ) THEN
    RAISE EXCEPTION 'registration_intent has pending rows - resolve before dropping the table';
  END IF;
END $$;

DROP TRIGGER IF EXISTS registration_intent_tenant_guard ON "registration_intent";
DROP FUNCTION IF EXISTS openkey_registration_intent_tenant_guard();

DROP TABLE IF EXISTS "registration_intent";

DROP TYPE IF EXISTS "RegistrationIntentStatus";
