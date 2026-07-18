-- Managed-account Phase A foundation. The preceding origin-main catch-up
-- migration creates every legacy object this migration alters.

CREATE TYPE "KeyPurpose" AS ENUM ('PERSONAL', 'MANAGED_ACCOUNT');
CREATE TYPE "OrganizationCredentialKind" AS ENUM ('BROKER', 'PROVISIONER');
CREATE TYPE "OrganizationRole" AS ENUM ('ADMIN', 'MEMBER');
CREATE TYPE "MembershipStatus" AS ENUM ('ACTIVE', 'REVOKED');
CREATE TYPE "RegistrationIntentStatus" AS ENUM ('PENDING', 'CONSUMED', 'EXPIRED', 'FAILED');
CREATE TYPE "ManagedAccountState" AS ENUM ('PROVISIONED', 'MANAGED', 'EJECTING', 'USER_OWNED', 'EXPIRED', 'FAILED');
CREATE TYPE "CustodianType" AS ENUM ('ORGANIZATION', 'USER');
CREATE TYPE "RevocationStatus" AS ENUM ('NOT_REQUIRED', 'PENDING', 'REVOKED');
CREATE TYPE "NodeRole" AS ENUM ('HOST', 'REPLICA');
CREATE TYPE "RevocationReceiptStatus" AS ENUM ('PENDING', 'SUBMITTED', 'CONFIRMED', 'FAILED');

ALTER TABLE "session" ADD COLUMN "lastPasskeyAt" TIMESTAMP(3);
ALTER TABLE "ethereum_keys" ADD COLUMN "keyPurpose" "KeyPurpose" NOT NULL DEFAULT 'PERSONAL';
ALTER TABLE "ethereum_keys" ADD COLUMN "sealingContext" TEXT;
ALTER TABLE "oauth_client" ADD COLUMN "organizationId" TEXT;
ALTER TABLE "developer_account" ADD COLUMN "organizationId" TEXT;
CREATE UNIQUE INDEX "oauth_client_clientId_organizationId_key" ON "oauth_client"("clientId", "organizationId");
CREATE INDEX "oauth_client_organizationId_idx" ON "oauth_client"("organizationId");
CREATE UNIQUE INDEX "developer_account_organizationId_key" ON "developer_account"("organizationId");
CREATE UNIQUE INDEX "ethereum_keys_id_userId_key" ON "ethereum_keys"("id", "userId");
CREATE INDEX "ethereum_keys_userId_keyPurpose_idx" ON "ethereum_keys"("userId", "keyPurpose");
DROP INDEX IF EXISTS "ethereum_keys_userId_idx";

CREATE TABLE "organization" (
  "id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "plan" "Plan" NOT NULL DEFAULT 'FREE',
  "billingState" "BillingState" NOT NULL DEFAULT 'FREE',
  "stripeCustomerId" TEXT,
  "stripeSubscriptionId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "organization_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "organization_stripeCustomerId_key" ON "organization"("stripeCustomerId");

CREATE TABLE "organization_membership" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "role" "OrganizationRole" NOT NULL DEFAULT 'MEMBER',
  "status" "MembershipStatus" NOT NULL DEFAULT 'ACTIVE',
  "validFrom" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "validUntil" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "organization_membership_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "organization_membership_interval_check" CHECK ("validUntil" IS NULL OR "validFrom" < "validUntil"),
  CONSTRAINT "organization_membership_status_check" CHECK (("status" = 'ACTIVE' AND "revokedAt" IS NULL) OR ("status" = 'REVOKED' AND "revokedAt" IS NOT NULL))
);
CREATE UNIQUE INDEX "organization_membership_org_user_from_key" ON "organization_membership"("organizationId", "userId", "validFrom");
CREATE INDEX "organization_membership_org_status_idx" ON "organization_membership"("organizationId", "status");
CREATE INDEX "organization_membership_user_status_idx" ON "organization_membership"("userId", "status");

CREATE TABLE "organization_server_credential" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "secretHash" TEXT NOT NULL,
  "secretPrefix" TEXT NOT NULL,
  "subjectUserId" TEXT,
  "kind" "OrganizationCredentialKind" NOT NULL DEFAULT 'BROKER',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastUsedAt" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  CONSTRAINT "organization_server_credential_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "organization_server_credential_secretPrefix_key" ON "organization_server_credential"("secretPrefix");
CREATE INDEX "organization_server_credential_org_revoked_idx" ON "organization_server_credential"("organizationId", "revokedAt");

CREATE TABLE "plan_entitlements" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "version" INTEGER NOT NULL DEFAULT 1,
  "maxApps" INTEGER NOT NULL,
  "maxOrganizationMembers" INTEGER NOT NULL,
  "maxManagedAccounts" INTEGER NOT NULL,
  "monthlyActiveManagedUsers" INTEGER NOT NULL,
  "storageBytesPerManagedAccount" BIGINT NOT NULL,
  "requestsPerMinute" INTEGER NOT NULL,
  "maxTenantDelegationTtlSeconds" INTEGER NOT NULL,
  "maxTenantPolicyVersion" INTEGER NOT NULL,
  "webhookDelivery" BOOLEAN NOT NULL DEFAULT false,
  "auditRetentionDays" INTEGER NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "plan_entitlements_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "plan_entitlements_organizationId_key" ON "plan_entitlements"("organizationId");

CREATE TABLE "registration_intent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "publicClientId" TEXT NOT NULL,
  "externalUserId" TEXT NOT NULL,
  "redirectUri" TEXT NOT NULL,
  "policyTemplate" TEXT NOT NULL,
  "policyVersion" INTEGER NOT NULL DEFAULT 1,
  "nonce" TEXT NOT NULL,
  "idempotencyKey" TEXT NOT NULL,
  "metadata" JSONB,
  "status" "RegistrationIntentStatus" NOT NULL DEFAULT 'PENDING',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "consumedAt" TIMESTAMP(3),
  CONSTRAINT "registration_intent_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "registration_intent_nonce_key" ON "registration_intent"("nonce");
CREATE UNIQUE INDEX "registration_intent_org_idempotency_key" ON "registration_intent"("organizationId", "idempotencyKey");
CREATE INDEX "registration_intent_org_external_idx" ON "registration_intent"("organizationId", "externalUserId");
CREATE INDEX "registration_intent_status_expiry_idx" ON "registration_intent"("status", "expiresAt");

CREATE TABLE "managed_account" (
  "id" TEXT NOT NULL,
  "ownerUserId" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "externalUserId" TEXT NOT NULL,
  "keyId" TEXT NOT NULL,
  "custodyHeadId" TEXT,
  "policyTemplate" TEXT NOT NULL DEFAULT 'tinycloud-standard-v1',
  "state" "ManagedAccountState" NOT NULL DEFAULT 'PROVISIONED',
  "custodyEpoch" INTEGER NOT NULL DEFAULT 0,
  "policyVersion" INTEGER NOT NULL DEFAULT 1,
  "tenantParentDelegationCid" TEXT,
  "revocationStatus" "RevocationStatus" NOT NULL DEFAULT 'NOT_REQUIRED',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "managed_account_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "managed_account_epoch_positive_check" CHECK ("custodyEpoch" >= 0)
);
CREATE UNIQUE INDEX "managed_account_keyId_key" ON "managed_account"("keyId");
CREATE UNIQUE INDEX "managed_account_custodyHeadId_key" ON "managed_account"("custodyHeadId");
CREATE UNIQUE INDEX "managed_account_org_external_key" ON "managed_account"("organizationId", "externalUserId");
CREATE UNIQUE INDEX "managed_account_key_owner_key" ON "managed_account"("keyId", "ownerUserId");
CREATE UNIQUE INDEX "managed_account_id_keyId_key" ON "managed_account"("id", "keyId");
CREATE UNIQUE INDEX "managed_account_head_account_key" ON "managed_account"("custodyHeadId", "id");
CREATE INDEX "managed_account_owner_idx" ON "managed_account"("ownerUserId");
CREATE INDEX "managed_account_org_state_idx" ON "managed_account"("organizationId", "state");

CREATE TABLE "key_custody" (
  "id" TEXT NOT NULL,
  "managedAccountId" TEXT NOT NULL,
  "custodianType" "CustodianType" NOT NULL,
  "custodianId" TEXT NOT NULL,
  "epoch" INTEGER NOT NULL,
  "activatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "revokedAt" TIMESTAMP(3),
  CONSTRAINT "key_custody_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "key_custody_epoch_positive_check" CHECK ("epoch" > 0)
);
CREATE UNIQUE INDEX "key_custody_account_epoch_key" ON "key_custody"("managedAccountId", "epoch");
CREATE UNIQUE INDEX "key_custody_id_account_key" ON "key_custody"("id", "managedAccountId");
CREATE INDEX "key_custody_account_revoked_idx" ON "key_custody"("managedAccountId", "revokedAt");

CREATE TABLE "managed_account_policy" (
  "id" TEXT NOT NULL,
  "managedAccountId" TEXT NOT NULL,
  "version" INTEGER NOT NULL,
  "template" TEXT NOT NULL,
  "grants" JSONB NOT NULL,
  "maxTtlSeconds" INTEGER NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "managed_account_policy_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "managed_account_policy_account_version_key" ON "managed_account_policy"("managedAccountId", "version");

CREATE TABLE "possession_event" (
  "id" TEXT NOT NULL,
  "managedAccountId" TEXT NOT NULL,
  "keyId" TEXT NOT NULL,
  "epoch" INTEGER NOT NULL,
  "previousEventHash" TEXT,
  "eventHash" TEXT NOT NULL,
  "fromPrincipal" TEXT NOT NULL,
  "toPrincipal" TEXT NOT NULL,
  "reason" TEXT NOT NULL,
  "credentialPolicyHash" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "accountKeySignature" TEXT NOT NULL,
  "witnessReceipt" JSONB,
  CONSTRAINT "possession_event_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "possession_event_signature_check" CHECK (length(trim("accountKeySignature")) > 0)
);
CREATE UNIQUE INDEX "possession_event_eventHash_key" ON "possession_event"("eventHash");
CREATE UNIQUE INDEX "possession_event_account_epoch_key" ON "possession_event"("managedAccountId", "epoch");
CREATE UNIQUE INDEX "possession_event_id_account_key" ON "possession_event"("id", "managedAccountId");
CREATE INDEX "possession_event_account_created_idx" ON "possession_event"("managedAccountId", "createdAt");

CREATE TABLE "managed_account_node" (
  "id" TEXT NOT NULL,
  "managedAccountId" TEXT NOT NULL,
  "nodeId" TEXT NOT NULL,
  "baseUrl" TEXT NOT NULL,
  "role" "NodeRole" NOT NULL,
  "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastConfirmedAt" TIMESTAMP(3),
  "active" BOOLEAN NOT NULL DEFAULT true,
  CONSTRAINT "managed_account_node_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "managed_account_node_account_node_key" ON "managed_account_node"("managedAccountId", "nodeId");
CREATE UNIQUE INDEX "managed_account_node_id_account_key" ON "managed_account_node"("id", "managedAccountId");
CREATE INDEX "managed_account_node_account_active_idx" ON "managed_account_node"("managedAccountId", "active");

CREATE TABLE "eject_revocation_receipt" (
  "id" TEXT NOT NULL,
  "possessionEventId" TEXT NOT NULL,
  "nodeId" TEXT NOT NULL,
  "managedAccountId" TEXT NOT NULL,
  "tenantParentDelegationCid" TEXT NOT NULL,
  "submittedAt" TIMESTAMP(3),
  "confirmedAt" TIMESTAMP(3),
  "status" "RevocationReceiptStatus" NOT NULL DEFAULT 'PENDING',
  "responseDigest" TEXT,
  CONSTRAINT "eject_revocation_receipt_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "eject_receipt_event_node_key" ON "eject_revocation_receipt"("possessionEventId", "nodeId");
CREATE INDEX "eject_receipt_node_status_idx" ON "eject_revocation_receipt"("nodeId", "status");

ALTER TABLE "developer_account" ADD CONSTRAINT "developer_account_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "oauth_client" ADD CONSTRAINT "oauth_client_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "organization_membership" ADD CONSTRAINT "membership_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "organization_membership" ADD CONSTRAINT "membership_user_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "organization_server_credential" ADD CONSTRAINT "credential_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "organization_server_credential" ADD CONSTRAINT "credential_subject_fkey" FOREIGN KEY ("subjectUserId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "plan_entitlements" ADD CONSTRAINT "plan_entitlements_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "registration_intent" ADD CONSTRAINT "registration_intent_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "registration_intent" ADD CONSTRAINT "registration_intent_client_org_fkey" FOREIGN KEY ("publicClientId", "organizationId") REFERENCES "oauth_client"("clientId", "organizationId") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "managed_account" ADD CONSTRAINT "managed_account_owner_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "managed_account" ADD CONSTRAINT "managed_account_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "managed_account" ADD CONSTRAINT "managed_account_key_owner_fkey" FOREIGN KEY ("keyId", "ownerUserId") REFERENCES "ethereum_keys"("id", "userId") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "key_custody" ADD CONSTRAINT "key_custody_account_fkey" FOREIGN KEY ("managedAccountId") REFERENCES "managed_account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "managed_account" ADD CONSTRAINT "managed_account_head_fkey" FOREIGN KEY ("custodyHeadId", "id") REFERENCES "key_custody"("id", "managedAccountId") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "managed_account_policy" ADD CONSTRAINT "managed_policy_account_fkey" FOREIGN KEY ("managedAccountId") REFERENCES "managed_account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "possession_event" ADD CONSTRAINT "possession_event_account_key_fkey" FOREIGN KEY ("managedAccountId", "keyId") REFERENCES "managed_account"("id", "keyId") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "managed_account_node" ADD CONSTRAINT "node_account_fkey" FOREIGN KEY ("managedAccountId") REFERENCES "managed_account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "eject_revocation_receipt" ADD CONSTRAINT "receipt_account_fkey" FOREIGN KEY ("managedAccountId") REFERENCES "managed_account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "eject_revocation_receipt" ADD CONSTRAINT "receipt_event_account_fkey" FOREIGN KEY ("possessionEventId", "managedAccountId") REFERENCES "possession_event"("id", "managedAccountId") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "eject_revocation_receipt" ADD CONSTRAINT "receipt_node_account_fkey" FOREIGN KEY ("nodeId", "managedAccountId") REFERENCES "managed_account_node"("id", "managedAccountId") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "ethereum_keys" ADD CONSTRAINT "ethereum_keys_sealing_context_format_check"
  CHECK ("sealingContext" IS NULL OR "sealingContext" ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$');
CREATE UNIQUE INDEX "ethereum_keys_sealingContext_key" ON "ethereum_keys"("sealingContext");

CREATE OR REPLACE FUNCTION openkey_immutable_key_classification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW."keyType" = 'MANAGED' AND (NEW."sealingContext" IS NULL OR NEW."sealedBlob" IS NULL) THEN
    RAISE EXCEPTION 'new managed keys require a sealing context and sealed blob';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW."keyType" IS DISTINCT FROM OLD."keyType" THEN
    RAISE EXCEPTION 'key type is immutable';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW."keyPurpose" IS DISTINCT FROM OLD."keyPurpose" THEN
    RAISE EXCEPTION 'key purpose is immutable';
  END IF;
  IF TG_OP = 'UPDATE' AND EXISTS (SELECT 1 FROM "managed_account" WHERE "keyId" = OLD."id")
     AND (NEW."address" IS DISTINCT FROM OLD."address" OR NEW."publicKey" IS DISTINCT FROM OLD."publicKey"
       OR NEW."userId" IS DISTINCT FROM OLD."userId") THEN
    RAISE EXCEPTION 'bound managed key identity is immutable';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW."keyType" = 'MANAGED' AND NEW."sealedBlob" IS NULL
     AND EXISTS (SELECT 1 FROM "managed_account" WHERE "keyId" = NEW."id" AND "ownerUserId" = NEW."userId") THEN
    RAISE EXCEPTION 'bound managed keys require a sealed blob';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW."sealingContext" IS DISTINCT FROM OLD."sealingContext" THEN
    RAISE EXCEPTION 'sealing context is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER ethereum_keys_classification_guard BEFORE INSERT OR UPDATE ON "ethereum_keys"
  FOR EACH ROW EXECUTE FUNCTION openkey_immutable_key_classification();

CREATE OR REPLACE FUNCTION openkey_managed_key_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE key_type "KeyType"; key_purpose "KeyPurpose"; sealed TEXT; context TEXT;
BEGIN
  SELECT "keyType", "keyPurpose", "sealedBlob", "sealingContext" INTO key_type, key_purpose, sealed, context
    FROM "ethereum_keys" WHERE "id" = NEW."keyId" AND "userId" = NEW."ownerUserId";
  IF key_type IS DISTINCT FROM 'MANAGED' OR key_purpose IS DISTINCT FROM 'MANAGED_ACCOUNT'
     OR sealed IS NULL OR context IS NULL THEN
    RAISE EXCEPTION 'managed accounts require a managed-account key with immutable sealing material';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER managed_account_key_guard BEFORE INSERT OR UPDATE OF "keyId", "ownerUserId" ON "managed_account"
  FOR EACH ROW EXECUTE FUNCTION openkey_managed_key_guard();

CREATE OR REPLACE FUNCTION openkey_managed_account_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."ownerUserId" IS DISTINCT FROM OLD."ownerUserId"
     OR NEW."organizationId" IS DISTINCT FROM OLD."organizationId"
     OR NEW."externalUserId" IS DISTINCT FROM OLD."externalUserId"
     OR NEW."keyId" IS DISTINCT FROM OLD."keyId" THEN
    RAISE EXCEPTION 'managed account identity is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER managed_account_identity_guard BEFORE UPDATE ON "managed_account"
  FOR EACH ROW EXECUTE FUNCTION openkey_managed_account_identity_guard();

CREATE OR REPLACE FUNCTION openkey_managed_account_state_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."state" IS DISTINCT FROM OLD."state"
     AND NOT (
       (OLD."state" = 'PROVISIONED' AND NEW."state" IN ('MANAGED', 'EXPIRED', 'FAILED'))
       OR (OLD."state" = 'FAILED' AND NEW."state" = 'PROVISIONED')
       OR (OLD."state" = 'MANAGED' AND NEW."state" IN ('EJECTING', 'USER_OWNED'))
       OR (OLD."state" = 'EJECTING' AND NEW."state" IN ('MANAGED', 'USER_OWNED'))
     ) THEN
    RAISE EXCEPTION 'managed account lifecycle transition % -> % is not allowed', OLD."state", NEW."state";
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER managed_account_state_guard BEFORE UPDATE OF "state" ON "managed_account"
  FOR EACH ROW EXECUTE FUNCTION openkey_managed_account_state_guard();

CREATE OR REPLACE FUNCTION openkey_append_only_history_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END;
$$;

CREATE OR REPLACE FUNCTION openkey_membership_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."organizationId" IS DISTINCT FROM OLD."organizationId" OR NEW."userId" IS DISTINCT FROM OLD."userId"
     OR NEW."validFrom" IS DISTINCT FROM OLD."validFrom" OR NEW."role" IS DISTINCT FROM OLD."role" THEN
    RAISE EXCEPTION 'membership identity is append-only';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER membership_identity_guard BEFORE UPDATE ON "organization_membership"
  FOR EACH ROW EXECUTE FUNCTION openkey_membership_identity_guard();
CREATE TRIGGER membership_delete_guard BEFORE DELETE ON "organization_membership"
  FOR EACH ROW EXECUTE FUNCTION openkey_append_only_history_guard();

CREATE OR REPLACE FUNCTION openkey_custody_history_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE account_state "ManagedAccountState";
BEGIN
  SELECT "state" INTO account_state FROM "managed_account"
    WHERE "id" = COALESCE(NEW."managedAccountId", OLD."managedAccountId");
  IF account_state = 'USER_OWNED' THEN
    RAISE EXCEPTION 'user-owned custody history is terminal';
  END IF;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'custody history is immutable'; END IF;
  IF NEW."id" IS DISTINCT FROM OLD."id"
     OR NEW."managedAccountId" IS DISTINCT FROM OLD."managedAccountId"
     OR NEW."epoch" IS DISTINCT FROM OLD."epoch"
     OR NEW."custodianType" IS DISTINCT FROM OLD."custodianType"
     OR NEW."custodianId" IS DISTINCT FROM OLD."custodianId"
     OR NEW."activatedAt" IS DISTINCT FROM OLD."activatedAt" THEN
    RAISE EXCEPTION 'custody identity is immutable';
  END IF;
  IF OLD."revokedAt" IS NOT NULL OR NEW."revokedAt" IS NULL OR NEW."revokedAt" < OLD."activatedAt" THEN
    RAISE EXCEPTION 'custody revocation is one-way';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER key_custody_history_guard BEFORE UPDATE OR DELETE ON "key_custody"
  FOR EACH ROW EXECUTE FUNCTION openkey_custody_history_guard();

CREATE OR REPLACE FUNCTION openkey_custody_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE account_state "ManagedAccountState";
BEGIN
  SELECT "state" INTO account_state FROM "managed_account" WHERE "id" = NEW."managedAccountId";
  IF account_state = 'USER_OWNED' THEN
    RAISE EXCEPTION 'user-owned custody is terminal';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER key_custody_insert_guard BEFORE INSERT ON "key_custody"
  FOR EACH ROW EXECUTE FUNCTION openkey_custody_insert_guard();

CREATE OR REPLACE FUNCTION openkey_possession_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE account_state "ManagedAccountState";
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT "state" INTO account_state FROM "managed_account" WHERE "id" = NEW."managedAccountId";
    IF account_state = 'USER_OWNED' THEN
      RAISE EXCEPTION 'user-owned possession history is terminal';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'possession events are append-only'; END IF;
  IF NEW."id" IS DISTINCT FROM OLD."id"
     OR NEW."managedAccountId" IS DISTINCT FROM OLD."managedAccountId"
     OR NEW."keyId" IS DISTINCT FROM OLD."keyId"
     OR NEW."epoch" IS DISTINCT FROM OLD."epoch"
     OR NEW."previousEventHash" IS DISTINCT FROM OLD."previousEventHash"
     OR NEW."eventHash" IS DISTINCT FROM OLD."eventHash"
     OR NEW."fromPrincipal" IS DISTINCT FROM OLD."fromPrincipal"
     OR NEW."toPrincipal" IS DISTINCT FROM OLD."toPrincipal"
     OR NEW."reason" IS DISTINCT FROM OLD."reason"
     OR NEW."credentialPolicyHash" IS DISTINCT FROM OLD."credentialPolicyHash"
     OR NEW."createdAt" IS DISTINCT FROM OLD."createdAt"
     OR NEW."accountKeySignature" IS DISTINCT FROM OLD."accountKeySignature" THEN
    RAISE EXCEPTION 'possession event is append-only';
  END IF;
  -- witnessReceipt is the one intentionally mutable integration field. It may
  -- evolve after USER_OWNED, but no protocol field may change with it.
  RETURN NEW;
END;
$$;
CREATE TRIGGER possession_event_append_only BEFORE INSERT OR UPDATE OR DELETE ON "possession_event"
  FOR EACH ROW EXECUTE FUNCTION openkey_possession_event_guard();

CREATE OR REPLACE FUNCTION openkey_custody_epoch_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD."state" = 'USER_OWNED' THEN
    RAISE EXCEPTION 'user-owned custody epoch is terminal';
  ELSIF OLD."state" = 'PROVISIONED' AND OLD."custodyEpoch" = 0 AND OLD."custodyHeadId" IS NULL THEN
    IF NEW."custodyEpoch" <> 1 OR NEW."custodyHeadId" IS NULL OR NEW."state" <> 'MANAGED' THEN
      RAISE EXCEPTION 'initial custody activation must be epoch 1 organization custody';
    END IF;
  ELSIF OLD."state" IN ('MANAGED', 'EJECTING')
    AND (NEW."custodyEpoch" <> OLD."custodyEpoch" + 1
      OR NEW."custodyHeadId" IS NULL OR NEW."state" <> 'USER_OWNED') THEN
    RAISE EXCEPTION 'only the owner custody transfer may advance the custody epoch';
  ELSIF OLD."state" NOT IN ('MANAGED', 'EJECTING') THEN
    RAISE EXCEPTION 'custody epoch cannot change in lifecycle state %', OLD."state";
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER managed_account_epoch_guard BEFORE UPDATE OF "custodyEpoch", "custodyHeadId" ON "managed_account"
  FOR EACH ROW WHEN (OLD."custodyEpoch" IS DISTINCT FROM NEW."custodyEpoch" OR OLD."custodyHeadId" IS DISTINCT FROM NEW."custodyHeadId")
  EXECUTE FUNCTION openkey_custody_epoch_guard();

CREATE OR REPLACE FUNCTION openkey_validate_custody_account(account_id TEXT) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  state_value "ManagedAccountState";
  epoch_value INTEGER;
  head_id TEXT;
  owner_id TEXT;
  organization_id TEXT;
  key_id TEXT;
  custody_count INTEGER;
  unrevoked INTEGER;
  event_count INTEGER;
  epoch_one_custody RECORD;
  epoch_two_custody RECORD;
  epoch_one_event RECORD;
  epoch_two_event RECORD;
BEGIN
  SELECT ma."state", ma."custodyEpoch", ma."custodyHeadId", ma."ownerUserId", ma."organizationId", ma."keyId"
    INTO state_value, epoch_value, head_id, owner_id, organization_id, key_id
    FROM "managed_account" AS ma WHERE ma."id" = account_id;
  IF state_value IS NULL THEN RAISE EXCEPTION 'managed account does not exist'; END IF;

  SELECT count(*)::INTEGER INTO custody_count FROM "key_custody" WHERE "managedAccountId" = account_id;
  SELECT count(*)::INTEGER INTO unrevoked FROM "key_custody" WHERE "managedAccountId" = account_id AND "revokedAt" IS NULL;
  SELECT count(*)::INTEGER INTO event_count FROM "possession_event" WHERE "managedAccountId" = account_id;

  IF state_value IN ('PROVISIONED', 'EXPIRED', 'FAILED') THEN
    IF epoch_value <> 0 OR head_id IS NOT NULL OR custody_count <> 0 OR event_count <> 0 THEN
      RAISE EXCEPTION 'inactive accounts have no custody history';
    END IF;
    RETURN;
  END IF;
  IF state_value IN ('MANAGED', 'EJECTING') THEN
    IF epoch_value <> 1 OR head_id IS NULL OR custody_count <> 1 OR event_count <> 1 OR unrevoked <> 1 THEN
      RAISE EXCEPTION 'managed custody requires exactly the epoch-1 organization history';
    END IF;
  ELSIF state_value = 'USER_OWNED' THEN
    IF epoch_value <> 2 OR head_id IS NULL OR custody_count <> 2 OR event_count <> 2 OR unrevoked <> 1 THEN
      RAISE EXCEPTION 'user custody requires exactly the epoch-1 and epoch-2 history';
    END IF;
  ELSE
    RAISE EXCEPTION 'unknown managed-account custody state';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM "passkey" WHERE "userId" = owner_id) THEN
    RAISE EXCEPTION 'managed accounts require an owner passkey';
  END IF;

  SELECT * INTO epoch_one_custody FROM "key_custody"
    WHERE "managedAccountId" = account_id AND "epoch" = 1;
  SELECT * INTO epoch_one_event FROM "possession_event"
    WHERE "managedAccountId" = account_id AND "epoch" = 1;
  IF epoch_one_custody."id" IS NULL OR epoch_one_event."id" IS NULL THEN
    RAISE EXCEPTION 'active managed accounts require canonical epoch 1 history';
  END IF;
  IF epoch_one_custody."custodianType" IS DISTINCT FROM 'ORGANIZATION'
     OR epoch_one_custody."custodianId" IS DISTINCT FROM organization_id THEN
    RAISE EXCEPTION 'custody epoch 1 must belong to the original organization';
  END IF;
  IF state_value IN ('MANAGED', 'EJECTING') AND epoch_one_custody."revokedAt" IS NOT NULL THEN
    RAISE EXCEPTION 'managed custody epoch 1 must be unrevoked';
  END IF;
  IF state_value = 'USER_OWNED' AND epoch_one_custody."revokedAt" IS NULL THEN
    RAISE EXCEPTION 'user custody epoch 1 must be revoked';
  END IF;
  IF epoch_one_event."keyId" IS DISTINCT FROM key_id
     OR epoch_one_event."previousEventHash" IS NOT NULL
     OR epoch_one_event."fromPrincipal" IS DISTINCT FROM 'none'
     OR epoch_one_event."toPrincipal" IS DISTINCT FROM ('organization:' || organization_id)
     OR epoch_one_event."reason" IS DISTINCT FROM 'INITIAL_ACTIVATION'
     OR length(trim(epoch_one_event."accountKeySignature")) = 0 THEN
    RAISE EXCEPTION 'epoch 1 event has non-canonical custody fields';
  END IF;
  IF head_id IS DISTINCT FROM epoch_one_custody."id" AND state_value IN ('MANAGED', 'EJECTING') THEN
    RAISE EXCEPTION 'managed custody head must be the epoch-1 organization row';
  END IF;

  IF state_value = 'USER_OWNED' THEN
    SELECT * INTO epoch_two_custody FROM "key_custody"
      WHERE "managedAccountId" = account_id AND "epoch" = 2;
    SELECT * INTO epoch_two_event FROM "possession_event"
      WHERE "managedAccountId" = account_id AND "epoch" = 2;
    IF epoch_two_custody."id" IS NULL OR epoch_two_event."id" IS NULL
       OR head_id IS DISTINCT FROM epoch_two_custody."id"
       OR epoch_two_custody."custodianType" IS DISTINCT FROM 'USER'
       OR epoch_two_custody."custodianId" IS DISTINCT FROM owner_id
       OR epoch_two_custody."revokedAt" IS NOT NULL THEN
      RAISE EXCEPTION 'user custody head must be the unrevoked epoch-2 owner row';
    END IF;
    IF epoch_two_event."keyId" IS DISTINCT FROM key_id
       OR epoch_two_event."previousEventHash" IS DISTINCT FROM epoch_one_event."eventHash"
       OR epoch_two_event."fromPrincipal" IS DISTINCT FROM ('organization:' || organization_id)
       OR epoch_two_event."toPrincipal" IS DISTINCT FROM ('user:' || owner_id)
       OR epoch_two_event."reason" IS DISTINCT FROM 'OWNER_REQUEST'
       OR length(trim(epoch_two_event."accountKeySignature")) = 0 THEN
      RAISE EXCEPTION 'epoch 2 event has non-canonical custody fields';
    END IF;
  END IF;
END;
$$;
CREATE OR REPLACE FUNCTION openkey_managed_account_custody_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM openkey_validate_custody_account(NEW."id"); RETURN NULL; END;
$$;
CREATE OR REPLACE FUNCTION openkey_key_custody_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM openkey_validate_custody_account(COALESCE(NEW."managedAccountId", OLD."managedAccountId")); RETURN NULL; END;
$$;
CREATE OR REPLACE FUNCTION openkey_possession_event_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM openkey_validate_custody_account(COALESCE(NEW."managedAccountId", OLD."managedAccountId")); RETURN NULL; END;
$$;
CREATE CONSTRAINT TRIGGER managed_account_custody_commit_guard AFTER INSERT OR UPDATE OF "state", "custodyEpoch", "custodyHeadId" ON "managed_account"
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openkey_managed_account_custody_commit_guard();
CREATE CONSTRAINT TRIGGER key_custody_custody_commit_guard AFTER INSERT OR UPDATE OR DELETE ON "key_custody"
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openkey_key_custody_commit_guard();
CREATE CONSTRAINT TRIGGER possession_event_custody_commit_guard AFTER INSERT OR UPDATE ON "possession_event"
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openkey_possession_event_commit_guard();
