-- Align persisted refresh tokens with @better-auth/oauth-provider 1.6.
-- Revocation is now a timestamp and authTime is retained for refreshed ID
-- token claims. Existing boolean revocations remain revoked after conversion.

ALTER TABLE "oauth_refresh_token"
  ADD COLUMN "authTime" TIMESTAMP(3);

ALTER TABLE "oauth_refresh_token"
  ALTER COLUMN "revoked" DROP DEFAULT,
  ALTER COLUMN "revoked" TYPE TIMESTAMP(3)
    USING (CASE WHEN "revoked" THEN "createdAt" ELSE NULL END),
  ALTER COLUMN "revoked" DROP NOT NULL;
