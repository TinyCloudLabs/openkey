-- Tenant-managed account guard hardening and ownership backfill.

UPDATE "managed_account" ma
SET "subjectEmail" = lower(btrim(u."email", E'\t\n\r\x0c\x0b '))
FROM "user" u
WHERE ma."ownerUserId" = u."id"
  AND lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) IS DISTINCT FROM ma."subjectEmail";

UPDATE "ethereum_keys" ek
SET "userId" = ma."ownerUserId"
FROM "managed_account" ma
WHERE ma."keyId" = ek."id"
  AND ma."ownerUserId" IS NOT NULL
  AND ek."userId" IS DISTINCT FROM ma."ownerUserId";

CREATE OR REPLACE FUNCTION openkey_immutable_key_classification() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner_user_id TEXT;
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
  IF TG_OP = 'UPDATE' AND EXISTS (SELECT 1 FROM "managed_account" WHERE "keyId" = OLD."id") THEN
    IF NEW."address" IS DISTINCT FROM OLD."address" OR NEW."publicKey" IS DISTINCT FROM OLD."publicKey" THEN
      RAISE EXCEPTION 'bound managed key identity is immutable';
    END IF;
    SELECT "ownerUserId" INTO owner_user_id
      FROM "managed_account"
      WHERE "keyId" = OLD."id"
      LIMIT 1;
    IF owner_user_id IS NULL AND NEW."userId" IS NOT NULL THEN
      RAISE EXCEPTION 'managed key cannot be associated before account ownership is established';
    END IF;
    IF owner_user_id IS NOT NULL AND NEW."userId" IS DISTINCT FROM owner_user_id THEN
      RAISE EXCEPTION 'bound managed key ownership is immutable';
    END IF;
  END IF;
  IF TG_OP = 'UPDATE' AND NEW."sealingContext" IS DISTINCT FROM OLD."sealingContext" THEN
    RAISE EXCEPTION 'sealing context is immutable';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS ethereum_keys_classification_guard ON "ethereum_keys";
CREATE TRIGGER ethereum_keys_classification_guard BEFORE INSERT OR UPDATE ON "ethereum_keys"
  FOR EACH ROW EXECUTE FUNCTION openkey_immutable_key_classification();

CREATE OR REPLACE FUNCTION openkey_managed_key_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  key_type "KeyType";
  key_purpose "KeyPurpose";
  sealed TEXT;
  context TEXT;
  owner_user_id TEXT;
  key_user_id TEXT;
BEGIN
  SELECT "keyType", "keyPurpose", "sealedBlob", "sealingContext", "userId"
    INTO key_type, key_purpose, sealed, context, key_user_id
    FROM "ethereum_keys"
    WHERE "id" = NEW."keyId";
  SELECT "ownerUserId" INTO owner_user_id
    FROM "managed_account"
    WHERE "id" = NEW."id"
    LIMIT 1;
  IF key_type IS DISTINCT FROM 'MANAGED' OR key_purpose IS DISTINCT FROM 'MANAGED_ACCOUNT' OR sealed IS NULL OR context IS NULL THEN
    RAISE EXCEPTION 'managed accounts require a managed-account key with immutable sealing material';
  END IF;
  IF owner_user_id IS NULL THEN
    IF key_user_id IS NOT NULL THEN
      RAISE EXCEPTION 'managed accounts require the key and owner to be unbound before association';
    END IF;
  ELSIF key_user_id IS DISTINCT FROM owner_user_id THEN
    RAISE EXCEPTION 'managed accounts require account ownership and key ownership to match';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS managed_account_key_guard ON "managed_account";
CREATE CONSTRAINT TRIGGER managed_account_key_guard
  AFTER INSERT OR UPDATE OF "keyId", "ownerUserId" ON "managed_account"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION openkey_managed_key_guard();

CREATE OR REPLACE FUNCTION openkey_managed_account_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD."ownerUserId" IS NOT NULL AND NEW."ownerUserId" IS DISTINCT FROM OLD."ownerUserId" THEN
    RAISE EXCEPTION 'managed account ownership is immutable';
  END IF;
  IF NEW."organizationId" IS DISTINCT FROM OLD."organizationId"
     OR NEW."externalUserId" IS DISTINCT FROM OLD."externalUserId"
     OR NEW."keyId" IS DISTINCT FROM OLD."keyId" THEN
    RAISE EXCEPTION 'managed account identity is immutable';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS managed_account_identity_guard ON "managed_account";
CREATE TRIGGER managed_account_identity_guard BEFORE UPDATE ON "managed_account"
  FOR EACH ROW EXECUTE FUNCTION openkey_managed_account_identity_guard();

CREATE OR REPLACE FUNCTION openkey_managed_account_state_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."state" IS DISTINCT FROM OLD."state"
     AND NOT (
       (OLD."state" = 'PROVISIONED' AND NEW."state" IN ('MANAGED', 'DISABLED', 'EXPIRED', 'FAILED'))
       OR (OLD."state" = 'FAILED' AND NEW."state" = 'PROVISIONED')
       OR (OLD."state" = 'MANAGED' AND NEW."state" IN ('DISABLED', 'EJECTING', 'USER_OWNED'))
       OR (OLD."state" = 'DISABLED' AND NEW."state" IN ('MANAGED', 'EJECTING'))
       OR (OLD."state" = 'EJECTING' AND NEW."state" IN ('DISABLED', 'MANAGED', 'USER_OWNED'))
     ) THEN
    RAISE EXCEPTION 'managed account lifecycle transition % -> % is not allowed', OLD."state", NEW."state";
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS managed_account_state_guard ON "managed_account";
CREATE TRIGGER managed_account_state_guard BEFORE UPDATE OF "state" ON "managed_account"
  FOR EACH ROW EXECUTE FUNCTION openkey_managed_account_state_guard();

ALTER TABLE "managed_account"
  ADD CONSTRAINT "managed_account_subject_email_ascii_check"
  CHECK (
    "subjectEmail" = lower(btrim("subjectEmail", E'\t\n\r\x0c\x0b '))
    AND char_length("subjectEmail") <= 254
    AND octet_length("subjectEmail") = char_length("subjectEmail")
  );

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
  IF state_value IN ('MANAGED', 'EJECTING', 'DISABLED') THEN
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
  IF state_value IN ('MANAGED', 'EJECTING', 'DISABLED') AND epoch_one_custody."revokedAt" IS NOT NULL THEN
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
