ALTER TABLE "oauth_client" ADD COLUMN "tinycloudNativeDelegation" JSONB;

CREATE TABLE "tinycloud_native_consent_generation" (
  "userId" TEXT NOT NULL,
  "clientId" TEXT NOT NULL,
  "generation" BIGINT NOT NULL DEFAULT 0,
  CONSTRAINT "tinycloud_native_consent_generation_pkey" PRIMARY KEY ("userId", "clientId")
);

CREATE TABLE "tinycloud_native_request" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "clientId" TEXT NOT NULL,
  "redirectUri" TEXT NOT NULL,
  "state" TEXT NOT NULL,
  "codeChallenge" TEXT NOT NULL,
  "scopes" TEXT[] NOT NULL,
  "sessionDid" TEXT NOT NULL,
  "sessionJwk" JSONB NOT NULL,
  "sessionJkt" TEXT NOT NULL,
  "requestedPermissions" JSONB NOT NULL,
  "ttlSeconds" INTEGER NOT NULL,
  "siweNonce" TEXT,
  "status" TEXT NOT NULL DEFAULT 'PENDING',
  "userId" TEXT,
  "currentRevision" INTEGER NOT NULL DEFAULT 0,
  "approvedRevision" INTEGER,
  "consentGeneration" BIGINT,
  "signature" TEXT,
  "delegation" JSONB,
  "hosting" TEXT,
  "hostSignedAt" TIMESTAMP(3),
  "requestUriExpiresAt" TIMESTAMP(3) NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "tinycloud_native_request_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "oauth_client"("clientId") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "tinycloud_native_request_clientId_status_idx" ON "tinycloud_native_request"("clientId", "status");
CREATE INDEX "tinycloud_native_request_userId_clientId_status_idx" ON "tinycloud_native_request"("userId", "clientId", "status");
CREATE INDEX "tinycloud_native_request_expiresAt_idx" ON "tinycloud_native_request"("expiresAt");

CREATE TABLE "tinycloud_native_preparation" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "requestId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "userId" TEXT NOT NULL,
  "keyId" TEXT NOT NULL,
  "address" TEXT NOT NULL,
  "sessionSiwe" TEXT NOT NULL,
  "hostPlan" JSONB,
  "permissions" JSONB NOT NULL,
  "digest" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "tinycloud_native_preparation_requestId_fkey" FOREIGN KEY ("requestId") REFERENCES "tinycloud_native_request"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "tinycloud_native_preparation_requestId_revision_key" ON "tinycloud_native_preparation"("requestId", "revision");

CREATE TABLE "tinycloud_native_grant" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "userId" TEXT NOT NULL,
  "clientId" TEXT NOT NULL,
  "consentId" TEXT NOT NULL,
  "consentGeneration" BIGINT NOT NULL,
  "keyId" TEXT NOT NULL,
  "address" TEXT NOT NULL,
  "sessionDid" TEXT NOT NULL,
  "sessionJwk" JSONB NOT NULL,
  "sessionJkt" TEXT NOT NULL,
  "spaceId" TEXT NOT NULL,
  "approvedPermissions" JSONB NOT NULL,
  "ttlSeconds" INTEGER NOT NULL,
  "tinycloudHost" TEXT NOT NULL,
  "refreshTokenHash" TEXT,
  "previousRefreshTokenHash" TEXT,
  "rotatedAt" TIMESTAMP(3),
  "status" TEXT NOT NULL DEFAULT 'ACTIVE',
  "revokedAt" TIMESTAMP(3),
  "revokedReason" TEXT,
  "absoluteExpiresAt" TIMESTAMP(3) NOT NULL,
  "lastRenewedAt" TIMESTAMP(3),
  "renewCount" INTEGER NOT NULL DEFAULT 0,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "tinycloud_native_grant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "tinycloud_native_grant_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "oauth_client"("clientId") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "tinycloud_native_grant_refreshTokenHash_key" ON "tinycloud_native_grant"("refreshTokenHash");
CREATE INDEX "tinycloud_native_grant_userId_clientId_status_idx" ON "tinycloud_native_grant"("userId", "clientId", "status");
CREATE INDEX "tinycloud_native_grant_previousRefreshTokenHash_idx" ON "tinycloud_native_grant"("previousRefreshTokenHash");

-- Statuses are a closed set: an unknown value can never satisfy a later
-- redemption or renewal predicate by accident.
ALTER TABLE "tinycloud_native_request" ADD CONSTRAINT "tinycloud_native_request_status_check"
  CHECK ("status" IN ('PENDING', 'RESOLVED', 'APPROVED', 'DENIED', 'WITHDRAWN', 'REDEEMED'));
ALTER TABLE "tinycloud_native_request" ADD CONSTRAINT "tinycloud_native_request_hosting_check"
  CHECK ("hosting" IS NULL OR "hosting" IN ('existing', 'created', 'failed'));
ALTER TABLE "tinycloud_native_grant" ADD CONSTRAINT "tinycloud_native_grant_status_check"
  CHECK ("status" IN ('ACTIVE', 'REVOKED'));

-- Withdrawing delegation consent for (OLD.userId, OLD.clientId), by any path:
-- the provider's delete/update-consent endpoints, a user or client cascade, or
-- direct SQL. The consent row is already locked by the triggering statement,
-- so this keeps the global lock order: consent, generation, requests, grants,
-- then token rows.
CREATE FUNCTION tinycloud_native_withdraw_consent() RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO "tinycloud_native_consent_generation" ("userId", "clientId", "generation")
    VALUES (OLD."userId", OLD."clientId", 1)
    ON CONFLICT ("userId", "clientId") DO UPDATE
      SET "generation" = "tinycloud_native_consent_generation"."generation" + 1;

  UPDATE "tinycloud_native_request" SET "status" = 'WITHDRAWN', "updatedAt" = CURRENT_TIMESTAMP
    WHERE "userId" = OLD."userId" AND "clientId" = OLD."clientId"
      AND "status" IN ('RESOLVED', 'APPROVED');

  UPDATE "tinycloud_native_grant" SET "status" = 'REVOKED', "revokedAt" = CURRENT_TIMESTAMP,
      "revokedReason" = 'consent_withdrawn'
    WHERE "userId" = OLD."userId" AND "clientId" = OLD."clientId"
      AND "status" <> 'REVOKED';

  DELETE FROM "oauth_access_token" WHERE "refreshId" IN (
    SELECT rt."id" FROM "oauth_refresh_token" rt
    JOIN "tinycloud_native_grant" g ON g."userId" = rt."userId" AND g."clientId" = rt."clientId"
    WHERE g."userId" = OLD."userId" AND g."clientId" = OLD."clientId"
      AND rt."token" IN (g."refreshTokenHash", g."previousRefreshTokenHash")
  );
  DELETE FROM "oauth_refresh_token" rt USING "tinycloud_native_grant" g
    WHERE g."userId" = OLD."userId" AND g."clientId" = OLD."clientId"
      AND rt."userId" = g."userId" AND rt."clientId" = g."clientId"
      AND rt."token" IN (g."refreshTokenHash", g."previousRefreshTokenHash");
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tinycloud_native_consent_deleted
  AFTER DELETE ON "oauth_consent" FOR EACH ROW
  EXECUTE FUNCTION tinycloud_native_withdraw_consent();

-- COALESCE: a NULL scope array or NULL element must count as withdrawal, not
-- as "unknown". Moving a consent row to another user or client withdraws it
-- from the old pair.
CREATE TRIGGER tinycloud_native_consent_scope_withdrawn
  AFTER UPDATE OF "scopes", "userId", "clientId" ON "oauth_consent" FOR EACH ROW
  WHEN (
    COALESCE('tinycloud:delegation' = ANY(OLD."scopes"), false) AND (
      NOT COALESCE('tinycloud:delegation' = ANY(NEW."scopes"), false) OR
      OLD."userId" IS DISTINCT FROM NEW."userId" OR
      OLD."clientId" IS DISTINCT FROM NEW."clientId"
    )
  )
  EXECUTE FUNCTION tinycloud_native_withdraw_consent();
