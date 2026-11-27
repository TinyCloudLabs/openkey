-- Manual rollback for 20261121_0003_native_withdraw_stepup_tokens (Prisma does not run down files).
-- Also delete the row for this migration from "_prisma_migrations" if rolling back a deployed DB.
-- Restores the function as 20261007_0001_tinycloud_native_foundation defined it.
CREATE OR REPLACE FUNCTION tinycloud_native_withdraw_consent() RETURNS TRIGGER AS $$
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
