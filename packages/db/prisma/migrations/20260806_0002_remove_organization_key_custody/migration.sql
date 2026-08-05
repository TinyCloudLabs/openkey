-- TC-488: Developer Organizations retain app administration only. This is a
-- forward-only destructive cutover; do not run it until the managed-key
-- disposition gate has confirmed that no tenant key is canonical or required
-- for recovery.

DROP TRIGGER IF EXISTS "oauth_tenant_lifecycle_guard" ON "oauth_client";
DROP TRIGGER IF EXISTS "oauth_access_token_tenant_lifecycle_guard" ON "oauth_access_token";
DROP TRIGGER IF EXISTS "oauth_refresh_token_tenant_lifecycle_guard" ON "oauth_refresh_token";
DROP TRIGGER IF EXISTS "ethereum_keys_classification_guard" ON "ethereum_keys";
DROP TRIGGER IF EXISTS "managed_account_custody_commit_guard" ON "managed_account";
DROP TRIGGER IF EXISTS "managed_account_epoch_guard" ON "managed_account";
DROP TRIGGER IF EXISTS "managed_account_identity_guard" ON "managed_account";
DROP TRIGGER IF EXISTS "managed_account_key_guard" ON "managed_account";
DROP TRIGGER IF EXISTS "managed_account_state_guard" ON "managed_account";
DROP TRIGGER IF EXISTS "key_custody_custody_commit_guard" ON "key_custody";
DROP TRIGGER IF EXISTS "key_custody_history_guard" ON "key_custody";
DROP TRIGGER IF EXISTS "key_custody_insert_guard" ON "key_custody";
DROP TRIGGER IF EXISTS "eject_request_guard" ON "eject_request";

ALTER TABLE "managed_account" DROP CONSTRAINT IF EXISTS "managed_account_head_fkey";
ALTER TABLE "key_custody" DROP CONSTRAINT IF EXISTS "key_custody_account_fkey";

DROP FUNCTION IF EXISTS "openkey_oauth_tenant_lifecycle_guard"();
DROP FUNCTION IF EXISTS "openkey_immutable_key_classification"();
DROP FUNCTION IF EXISTS "openkey_managed_key_guard"();
DROP FUNCTION IF EXISTS "openkey_managed_account_custody_commit_guard"();
DROP FUNCTION IF EXISTS "openkey_custody_epoch_guard"();
DROP FUNCTION IF EXISTS "openkey_managed_account_identity_guard"();
DROP FUNCTION IF EXISTS "openkey_managed_account_key_guard"();
DROP FUNCTION IF EXISTS "openkey_managed_account_state_guard"();
DROP FUNCTION IF EXISTS "openkey_custody_history_guard"();
DROP FUNCTION IF EXISTS "openkey_custody_insert_guard"();
DROP FUNCTION IF EXISTS "openkey_eject_request_guard"();

DROP TABLE IF EXISTS "eject_revocation_receipt";
DROP TABLE IF EXISTS "managed_account_node";
DROP TABLE IF EXISTS "possession_event";
DROP TABLE IF EXISTS "eject_request";
DROP TABLE IF EXISTS "webhook_delivery";
DROP TABLE IF EXISTS "webhook_endpoint";
DROP TABLE IF EXISTS "managed_account_policy";
DROP TABLE IF EXISTS "managed_account_operation";
DROP TABLE IF EXISTS "key_custody";
DROP TABLE IF EXISTS "managed_account";
DROP TABLE IF EXISTS "organization_server_credential";

-- Tenant-generated keys and their bootstrap state are not a user canonical
-- identity. Remove them before removing the discriminator so no sealed
-- tenant key or tenant TinyCloud space survives this cutover.
DELETE FROM "ethereum_keys" WHERE "keyPurpose" = 'MANAGED_ACCOUNT';
DROP INDEX IF EXISTS "ethereum_keys_userId_keyPurpose_idx";
-- The expand migration's canonical-key index includes keyPurpose in its
-- predicate, so PostgreSQL drops it with the column. Replace it with the
-- post-cutover equivalent to keep the one-canonical-key invariant durable.
DROP INDEX IF EXISTS "ethereum_keys_one_active_canonical_tinycloud_key";
ALTER TABLE "ethereum_keys" DROP COLUMN IF EXISTS "keyPurpose";
CREATE UNIQUE INDEX "ethereum_keys_one_active_canonical_tinycloud_key"
  ON "ethereum_keys" ("userId")
  WHERE "isCanonicalTinyCloud" = true
    AND "userId" IS NOT NULL
    AND "keyType" = 'MANAGED'
    AND "archivedAt" IS NULL;

ALTER TABLE "organization" DROP COLUMN IF EXISTS "brokerDid";
ALTER TABLE "plan_entitlements"
  DROP COLUMN IF EXISTS "maxManagedAccounts",
  DROP COLUMN IF EXISTS "monthlyActiveManagedUsers",
  DROP COLUMN IF EXISTS "storageBytesPerManagedAccount",
  DROP COLUMN IF EXISTS "maxTenantDelegationTtlSeconds",
  DROP COLUMN IF EXISTS "maxTenantPolicyVersion",
  DROP COLUMN IF EXISTS "webhookDelivery";
ALTER TABLE "oauth_client" DROP COLUMN IF EXISTS "mode";
UPDATE "oauth_client"
SET "metadata" = "metadata" - 'openkeyClientMode' - 'openkeyOrganizationId'
WHERE "metadata" IS NOT NULL;

DROP TYPE IF EXISTS "RevocationReceiptStatus";
DROP TYPE IF EXISTS "NodeRole";
DROP TYPE IF EXISTS "RevocationStatus";
DROP TYPE IF EXISTS "CustodianType";
DROP TYPE IF EXISTS "EjectRequestStatus";
DROP TYPE IF EXISTS "ManagedAccountState";
DROP TYPE IF EXISTS "OrganizationCredentialKind";
DROP TYPE IF EXISTS "OauthClientMode";
DROP TYPE IF EXISTS "KeyPurpose";
