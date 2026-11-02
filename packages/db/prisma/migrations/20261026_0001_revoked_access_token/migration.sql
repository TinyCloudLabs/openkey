-- TC-2104: access tokens revoked at /oauth2/revoke. A JWT access token has no stored row, so the
-- provider's revoke of one changes nothing. This table keeps a revoked token's key (the SHA-256 of
-- its signed part, never the token) until the token's own expiry; the token status check reads it.
-- Additive: one new table.
CREATE TABLE "revoked_access_token" (
  "token_hash" TEXT NOT NULL,
  "client_id" TEXT NOT NULL,
  "expires_at" TIMESTAMP(3) NOT NULL,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "revoked_access_token_pkey" PRIMARY KEY ("token_hash")
);

CREATE INDEX "revoked_access_token_expires_at_idx"
  ON "revoked_access_token"("expires_at");
