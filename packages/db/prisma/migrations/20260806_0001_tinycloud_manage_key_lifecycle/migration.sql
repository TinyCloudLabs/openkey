-- TC-487: explicit, monotonic ownership policy for canonical TinyCloud signing.
ALTER TABLE "user"
  ADD COLUMN "tinyCloudManageKeyMode" TEXT NOT NULL DEFAULT 'APP_MANAGED',
  ADD COLUMN "tinyCloudManageKeyPolicyEpoch" BIGINT NOT NULL DEFAULT 0,
  ADD CONSTRAINT "user_tinycloud_manage_key_mode_check"
    CHECK ("tinyCloudManageKeyMode" IN ('APP_MANAGED', 'USER_CONTROLLED_SHARED', 'USER_CONTROLLED_EXCLUSIVE'));

ALTER TABLE "tinycloud_manage_key_app_preference"
  ADD COLUMN "status" TEXT NOT NULL DEFAULT 'ENABLED',
  ADD COLUMN "clientNameSnapshot" TEXT,
  ADD COLUMN "clientUriSnapshot" TEXT,
  ADD COLUMN "consentWithdrawnAt" TIMESTAMP(3),
  ADD CONSTRAINT "tinycloud_manage_key_app_preference_status_check"
    CHECK ("status" IN ('ENABLED', 'DISABLED', 'CONSENT_WITHDRAWN'));

-- The prior cascade could erase the user's durable choice and activity when an
-- OAuth client was removed. Keep the client ID snapshot as the audit identity.
ALTER TABLE "tinycloud_manage_key_app_preference"
  DROP CONSTRAINT "tinycloud_manage_key_app_preference_clientId_fkey",
  ADD CONSTRAINT "tinycloud_manage_key_app_preference_clientId_fkey"
    FOREIGN KEY ("clientId") REFERENCES "oauth_client"("clientId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- A pre-existing active consent becomes an explicit grant before signing flips
-- to a fail-closed missing-row default.
INSERT INTO "tinycloud_manage_key_app_preference" ("userId", "clientId", "enabled", "status", "clientNameSnapshot", "clientUriSnapshot", "createdAt", "updatedAt")
SELECT c."userId", c."clientId", true, 'ENABLED', oc."name", oc."uri", NOW(), NOW()
FROM "oauth_consent" c
JOIN "oauth_client" oc ON oc."clientId" = c."clientId"
WHERE 'tinycloud:manage-key' = ANY(c."scopes")
ON CONFLICT ("userId", "clientId") DO UPDATE
SET "clientNameSnapshot" = COALESCE("tinycloud_manage_key_app_preference"."clientNameSnapshot", EXCLUDED."clientNameSnapshot"),
    "clientUriSnapshot" = COALESCE("tinycloud_manage_key_app_preference"."clientUriSnapshot", EXCLUDED."clientUriSnapshot");

CREATE TABLE "tinycloud_manage_key_control_event" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "policyEpoch" BIGINT NOT NULL,
  "action" TEXT NOT NULL,
  "mode" TEXT NOT NULL,
  "clientId" TEXT,
  "requestDigest" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "tinycloud_manage_key_control_event_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "tinycloud_manage_key_control_event_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "tinycloud_manage_key_control_event_userId_createdAt_idx" ON "tinycloud_manage_key_control_event"("userId", "createdAt");

CREATE TABLE "tinycloud_manage_key_signing_decision" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "clientId" TEXT NOT NULL,
  "policyEpoch" BIGINT NOT NULL,
  "allowed" BOOLEAN NOT NULL,
  "reason" TEXT NOT NULL,
  "requestDigest" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "tinycloud_manage_key_signing_decision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "tinycloud_manage_key_signing_decision_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "tinycloud_manage_key_signing_decision_userId_createdAt_idx" ON "tinycloud_manage_key_signing_decision"("userId", "createdAt");
CREATE INDEX "tinycloud_manage_key_signing_decision_userId_clientId_createdAt_idx" ON "tinycloud_manage_key_signing_decision"("userId", "clientId", "createdAt");
