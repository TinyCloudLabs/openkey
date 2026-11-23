-- Who asked for the account setup this row records: a small closed set written by OpenKey (see
-- apps/api provision-authority.ts, STORED_PROVISION_AUTHORITIES; a test keeps the two lists equal).
-- NULL on every row made before this column, and a row with no authority is not first-party:
-- the background retry does not read it.
ALTER TABLE "tinycloud_bootstrap_state" ADD COLUMN "authority" TEXT;
ALTER TABLE "tinycloud_bootstrap_state" ADD CONSTRAINT "tinycloud_bootstrap_state_authority_check"
  CHECK ("authority" IS NULL OR "authority" IN (
    'first-party-origin',
    'first-party-client',
    'first-party-native-client',
    'approval-request',
    'device-approval',
    'delegate-link-local'
  ));
