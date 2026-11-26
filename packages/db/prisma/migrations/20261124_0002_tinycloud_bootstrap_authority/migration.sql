-- Who asked for the account setup this row records: a small closed set written by OpenKey (see
-- apps/api provision-authority.ts, STORED_PROVISION_AUTHORITIES; a test keeps the two lists equal).
-- NULL on every row made before this column, and a row with no authority is not first-party:
-- the background retry does not read it.
-- The CHECK is added NOT VALID and is not validated here. Prisma applies this file in one transaction, so a VALIDATE
-- CONSTRAINT in it would hold the ACCESS EXCLUSIVE lock the ADD takes through a scan of the table and gain nothing.
-- NOT VALID still binds every row inserted or updated from now on, and every existing row has a NULL "authority", which
-- the CHECK accepts. An operator may run `ALTER TABLE "tinycloud_bootstrap_state" VALIDATE CONSTRAINT
-- "tinycloud_bootstrap_state_authority_check";` later: it takes SHARE UPDATE EXCLUSIVE and does not block writes.
ALTER TABLE "tinycloud_bootstrap_state" ADD COLUMN "authority" TEXT;
ALTER TABLE "tinycloud_bootstrap_state" ADD CONSTRAINT "tinycloud_bootstrap_state_authority_check"
  CHECK ("authority" IS NULL OR "authority" IN (
    'first-party-origin',
    'first-party-client',
    'first-party-native-client',
    'approval-request',
    'device-approval',
    'delegate-link-local'
  )) NOT VALID;
