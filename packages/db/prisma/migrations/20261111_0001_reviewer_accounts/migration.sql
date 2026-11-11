BEGIN;
ALTER TABLE "user" ADD COLUMN "reviewerHoldAt" TIMESTAMP(3);
ALTER TABLE session ADD COLUMN "reviewerEpoch" INTEGER;
ALTER TABLE oauth_consent ADD COLUMN "reviewerEpoch" INTEGER;
ALTER TABLE tinycloud_native_grant ADD COLUMN "reviewerEpoch" INTEGER;
CREATE TABLE reviewer_account (
  store TEXT PRIMARY KEY CHECK (store IN ('openai', 'google', 'apple')),
  email TEXT NOT NULL UNIQUE,
  "userId" TEXT UNIQUE REFERENCES "user"(id) ON DELETE SET NULL,
  "installEpoch" INTEGER NOT NULL DEFAULT 0,
  "clientId" TEXT, "redirectUri" TEXT, resource TEXT, "callbackUri" TEXT,
  "nodeHost" TEXT, "sessionDid" TEXT, "keyId" TEXT, "spaceId" TEXT,
  "seededAt" TIMESTAMP(3), "readyAt" TIMESTAMP(3), "grantSessionId" TEXT
);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM "user" WHERE lower(email) IN
    ('openai-review@tinycloud.xyz','google-review@tinycloud.xyz','appreview@tinycloud.xyz')) THEN
    RAISE EXCEPTION 'Reviewer email reservation conflicts with an existing user';
  END IF;
END $$;
INSERT INTO reviewer_account (store,email) VALUES
  ('openai','openai-review@tinycloud.xyz'),
  ('google','google-review@tinycloud.xyz'),
  ('apple','appreview@tinycloud.xyz');

-- Serializes late provider writes with install/unset and preserves their captured epoch.
CREATE FUNCTION check_reviewer_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE binding reviewer_account%ROWTYPE;
BEGIN
  SELECT * INTO binding FROM reviewer_account WHERE "userId" = NEW."userId" FOR SHARE;
  IF FOUND AND (
    NEW."reviewerEpoch" IS DISTINCT FROM binding."installEpoch"
    OR EXISTS (SELECT 1 FROM "user" WHERE id = NEW."userId" AND ("reviewerHoldAt" IS NOT NULL OR "lockedAt" IS NOT NULL))
  ) THEN
    RAISE EXCEPTION 'Reviewer authority ended';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER session_reviewer_epoch BEFORE INSERT OR UPDATE ON session
  FOR EACH ROW EXECUTE FUNCTION check_reviewer_epoch();
CREATE TRIGGER consent_reviewer_epoch BEFORE INSERT OR UPDATE ON oauth_consent
  FOR EACH ROW EXECUTE FUNCTION check_reviewer_epoch();
CREATE TRIGGER native_grant_reviewer_epoch BEFORE INSERT OR UPDATE ON tinycloud_native_grant
  FOR EACH ROW EXECUTE FUNCTION check_reviewer_epoch();

CREATE FUNCTION check_reviewer_token() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE binding reviewer_account%ROWTYPE;
BEGIN
  SELECT * INTO binding FROM reviewer_account WHERE "userId" = NEW."userId" FOR SHARE;
  IF FOUND AND (
    NEW."clientId" IS DISTINCT FROM binding."clientId"
    OR NOT EXISTS (SELECT 1 FROM session s JOIN "user" u ON u.id = s."userId"
      WHERE s.id = NEW."sessionId" AND s."userId" = binding."userId"
        AND s."reviewerEpoch" = binding."installEpoch" AND s."expiresAt" > (now() AT TIME ZONE 'UTC')
        AND u."reviewerHoldAt" IS NULL AND u."lockedAt" IS NULL)
  ) THEN
    RAISE EXCEPTION 'Reviewer authority ended';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER access_token_reviewer_epoch BEFORE INSERT OR UPDATE ON oauth_access_token
  FOR EACH ROW EXECUTE FUNCTION check_reviewer_token();
CREATE TRIGGER refresh_token_reviewer_epoch BEFORE INSERT OR UPDATE ON oauth_refresh_token
  FOR EACH ROW EXECUTE FUNCTION check_reviewer_token();
COMMIT;
