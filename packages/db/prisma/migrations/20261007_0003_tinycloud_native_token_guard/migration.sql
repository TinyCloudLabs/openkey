-- TC-773 O4: no live OAuth token can exist for a native grant that is not
-- ACTIVE. Code exchange commits the grant, links the refresh token hash, and
-- only then does the provider insert the refresh and access token rows, each
-- in its own statement. A consent withdrawal can land in between; its delete
-- then finds no token, and the later insert would leave a live token for a
-- REVOKED grant.
--
-- Each guard takes the grant FOR SHARE (the grant level of the global lock
-- order; the generation is only read, never locked, so the order is kept):
-- - a withdrawal that already revoked the grant is observed and the insert
--   fails with SQLSTATE TC773;
-- - a withdrawal still in flight holds the grant row, so the guard waits for
--   it to commit and then observes the revocation;
-- - an insert that takes the grant first makes the withdrawal's grant UPDATE
--   wait for it, and the withdrawal's later token DELETE then removes it.

CREATE FUNCTION tinycloud_native_assert_grant_live(token_hash TEXT) RETURNS BOOLEAN AS $$
DECLARE
  grant_row RECORD;
  current_generation BIGINT;
BEGIN
  SELECT g."status", g."userId", g."clientId", g."consentGeneration" INTO grant_row
    FROM "tinycloud_native_grant" g
    WHERE g."refreshTokenHash" = token_hash
    FOR SHARE;
  IF NOT FOUND THEN
    RETURN FALSE;
  END IF;
  -- A missing row is generation 0: the withdrawal trigger creates it at 1.
  SELECT COALESCE((SELECT c."generation"
    FROM "tinycloud_native_consent_generation" c
    WHERE c."userId" = grant_row."userId" AND c."clientId" = grant_row."clientId"), 0) INTO current_generation;
  IF grant_row."status" <> 'ACTIVE' OR current_generation <> grant_row."consentGeneration" THEN
    RAISE EXCEPTION 'tinycloud native grant is no longer active' USING ERRCODE = 'TC773';
  END IF;
  RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION tinycloud_native_refresh_token_guard() RETURNS TRIGGER AS $$
BEGIN
  PERFORM set_config('lock_timeout', '5s', true);
  PERFORM tinycloud_native_assert_grant_live(NEW."token");
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tinycloud_native_refresh_token_guard
  BEFORE INSERT ON "oauth_refresh_token" FOR EACH ROW
  EXECUTE FUNCTION tinycloud_native_refresh_token_guard();

-- An access token is native through its refresh token. A delegation-scoped
-- access token whose refresh row is already gone was withdrawn between the
-- two provider inserts, and is refused too.
CREATE FUNCTION tinycloud_native_access_token_guard() RETURNS TRIGGER AS $$
DECLARE
  refresh_hash TEXT;
BEGIN
  IF NEW."refreshId" IS NULL THEN
    RETURN NEW;
  END IF;
  PERFORM set_config('lock_timeout', '5s', true);
  SELECT rt."token" INTO refresh_hash FROM "oauth_refresh_token" rt WHERE rt."id" = NEW."refreshId";
  IF NOT FOUND THEN
    IF 'tinycloud:delegation' = ANY(COALESCE(NEW."scopes", ARRAY[]::TEXT[])) THEN
      RAISE EXCEPTION 'tinycloud native refresh token is no longer live' USING ERRCODE = 'TC773';
    END IF;
    RETURN NEW;
  END IF;
  PERFORM tinycloud_native_assert_grant_live(refresh_hash);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tinycloud_native_access_token_guard
  BEFORE INSERT ON "oauth_access_token" FOR EACH ROW
  EXECUTE FUNCTION tinycloud_native_access_token_guard();
