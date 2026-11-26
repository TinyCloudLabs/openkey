-- Manual rollback for 20261125_0002_bootstrap_authority_account_setup (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
-- Rows an account setup approval made lose their stored authority (NULL: not first-party, so the background retry
-- does not read them), then the narrow constraint of 20261124_0002 is restored, NOT VALID as there.
BEGIN;
SET LOCAL lock_timeout = '5s';
UPDATE "tinycloud_bootstrap_state" SET "authority" = NULL WHERE "authority" = 'account-setup';
ALTER TABLE "tinycloud_bootstrap_state" DROP CONSTRAINT "tinycloud_bootstrap_state_authority_check";
ALTER TABLE "tinycloud_bootstrap_state" ADD CONSTRAINT "tinycloud_bootstrap_state_authority_check"
  CHECK ("authority" IS NULL OR "authority" IN (
    'first-party-origin',
    'first-party-client',
    'first-party-native-client',
    'approval-request',
    'device-approval',
    'delegate-link-local'
  )) NOT VALID;
COMMIT;
