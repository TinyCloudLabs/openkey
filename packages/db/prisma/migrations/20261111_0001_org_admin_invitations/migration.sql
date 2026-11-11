ALTER TABLE "key_grants" ADD COLUMN "invitationTokenDigest" TEXT, ADD COLUMN "invitedUserId" TEXT,
  ADD COLUMN "invitationExpiresAt" TIMESTAMP(3), ADD COLUMN "granteeDid" TEXT;

CREATE UNIQUE INDEX "key_grants_one_accepted_account_per_key"
  ON "key_grants" ("keyId", "granteeUserId")
  WHERE "acceptedAt" IS NOT NULL AND "revokedAt" IS NULL AND "granteeUserId" IS NOT NULL;

CREATE TABLE "org_key_grant_challenges" (
  "nonce" TEXT PRIMARY KEY, "purpose" TEXT NOT NULL, "keyId" TEXT NOT NULL,
  "grantId" TEXT NOT NULL, "userId" TEXT NOT NULL, "sessionId" TEXT NOT NULL,
  "operationDigest" TEXT NOT NULL, "granteeDid" TEXT, "origin" TEXT NOT NULL, "rpId" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL, "consumedAt" TIMESTAMP(3), "result" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "org_key_grant_challenges_keyId_idx" ON "org_key_grant_challenges" ("keyId");
CREATE TABLE "key_grant_events" (
  "id" TEXT PRIMARY KEY, "keyId" TEXT NOT NULL, "grantId" TEXT NOT NULL,
  "actorUserId" TEXT NOT NULL, "kind" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "key_grant_events_keyId_createdAt_idx" ON "key_grant_events" ("keyId", "createdAt");
CREATE FUNCTION "deny_key_grant_event_mutation"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'key grant events are append-only'; END;
$$;
CREATE TRIGGER "key_grant_events_append_only" BEFORE UPDATE OR DELETE ON "key_grant_events"
  FOR EACH ROW EXECUTE FUNCTION "deny_key_grant_event_mutation"();

CREATE UNIQUE INDEX "key_grants_invitationTokenDigest_key" ON "key_grants" ("invitationTokenDigest");
