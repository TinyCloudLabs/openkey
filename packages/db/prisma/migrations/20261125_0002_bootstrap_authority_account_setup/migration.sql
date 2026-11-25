-- Adds 'account-setup' to the stored authorities a bootstrap row may carry: the owner approved the setup on OpenKey's
-- own account setup page (apps/api provision-authority.ts, STORED_PROVISION_AUTHORITIES; a test keeps the two lists
-- equal). The constraint is replaced, not altered: Postgres cannot change a CHECK in place.
-- lock_timeout: the DROP and the ADD each take ACCESS EXCLUSIVE on "tinycloud_bootstrap_state". Waiting behind a long
-- reader would queue every later read and write of the table behind this migration, so it gives up after five
-- seconds and the deploy fails instead; run it again. The migration runner sends each statement on its own, so the
-- script opens its own transaction: SET LOCAL applies only inside one, and the DROP and the ADD commit together.
-- NOT VALID, as in 20261124_0002: the ADD does not scan the table. Every existing value is in the wider list.
BEGIN;
SET LOCAL lock_timeout = '5s';
ALTER TABLE "tinycloud_bootstrap_state" DROP CONSTRAINT "tinycloud_bootstrap_state_authority_check";
ALTER TABLE "tinycloud_bootstrap_state" ADD CONSTRAINT "tinycloud_bootstrap_state_authority_check"
  CHECK ("authority" IS NULL OR "authority" IN (
    'first-party-origin',
    'first-party-client',
    'first-party-native-client',
    'approval-request',
    'device-approval',
    'delegate-link-local',
    'account-setup'
  )) NOT VALID;
COMMIT;
