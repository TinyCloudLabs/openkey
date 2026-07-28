-- Serialize tenant-managed OAuth token inserts with account lifecycle changes.
-- The trigger takes the same transaction-level advisory lock as disable and
-- ejection before a token can be persisted: an already-committed transition
-- is observed and rejected, while an insert that wins the lock race is
-- included in the transition's revocation UPDATE before that transition
-- commits.

CREATE OR REPLACE FUNCTION openkey_oauth_tenant_lifecycle_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  account_id TEXT;
  account_state "ManagedAccountState";
BEGIN
  FOR account_id IN
    SELECT ma."id"
    FROM "managed_account" ma
    JOIN "oauth_client" oc ON oc."organizationId" = ma."organizationId"
    JOIN "user" u ON u."id" = NEW."userId"
      AND lower(btrim(u."email", E'\t\n\r\x0c\x0b ')) = ma."subjectEmail"
    WHERE oc."clientId" = NEW."clientId"
      AND oc."mode" = 'TENANT_MANAGED'
  LOOP
    -- This transaction-level advisory lock is held by both token issuance and
    -- disable/ejection. It covers the provider's later token INSERT, not only
    -- the earlier lifecycle read, so a waiting trigger gets a fresh state.
    PERFORM pg_advisory_xact_lock(hashtext('oauth-lifecycle:' || account_id));
    SELECT ma."state" INTO account_state
      FROM "managed_account" ma
      WHERE ma."id" = account_id
      FOR UPDATE;
    IF account_state IS DISTINCT FROM 'MANAGED' THEN
      RAISE EXCEPTION 'tenant-managed OAuth token issuance is not allowed for account state %', account_state;
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS oauth_access_token_tenant_lifecycle_guard ON "oauth_access_token";
CREATE TRIGGER oauth_access_token_tenant_lifecycle_guard
  BEFORE INSERT ON "oauth_access_token"
  FOR EACH ROW EXECUTE FUNCTION openkey_oauth_tenant_lifecycle_guard();

DROP TRIGGER IF EXISTS oauth_refresh_token_tenant_lifecycle_guard ON "oauth_refresh_token";
CREATE TRIGGER oauth_refresh_token_tenant_lifecycle_guard
  BEFORE INSERT ON "oauth_refresh_token"
  FOR EACH ROW EXECUTE FUNCTION openkey_oauth_tenant_lifecycle_guard();
