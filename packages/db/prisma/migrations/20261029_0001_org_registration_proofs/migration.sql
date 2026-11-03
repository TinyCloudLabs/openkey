-- TC-128 S1b: durable session-bound consent and immutable per-intent registration receipts.
-- Additive only. Existing org custody, signing and cutover migrations remain unchanged.
CREATE TABLE "org_key_registration_challenges" (
    "challengeNonce" TEXT NOT NULL,
    "registrationId" TEXT NOT NULL,
    "ownerSubject" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "intentDigest" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "handle" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "assertionHash" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "org_key_registration_challenges_pkey" PRIMARY KEY ("challengeNonce"),
    CONSTRAINT "org_registration_challenge_consumption_check" CHECK (
        ("consumedAt" IS NULL) = ("assertionHash" IS NULL)
    ),
    CONSTRAINT "org_key_registration_challenges_sessionId_fkey"
        FOREIGN KEY ("sessionId") REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "org_key_registration_challenges_assertionHash_key"
    ON "org_key_registration_challenges"("assertionHash");
CREATE INDEX "org_key_registration_challenges_registrationId_idx"
    ON "org_key_registration_challenges"("registrationId");
CREATE INDEX "org_key_registration_challenges_expiresAt_idx"
    ON "org_key_registration_challenges"("expiresAt");

CREATE TABLE "org_key_registrations" (
    "registrationId" TEXT NOT NULL,
    "ownerSubject" TEXT NOT NULL,
    "intentDigest" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "handle" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "grantId" TEXT NOT NULL,
    "controllerDid" TEXT NOT NULL,
    "jti" TEXT NOT NULL,
    "proof" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "org_key_registrations_pkey" PRIMARY KEY ("registrationId"),
    CONSTRAINT "org_key_registrations_keyId_fkey"
        FOREIGN KEY ("keyId") REFERENCES "ethereum_keys"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "org_key_registrations_grantId_fkey"
        FOREIGN KEY ("grantId") REFERENCES "key_grants"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "org_key_registrations_keyId_key" ON "org_key_registrations"("keyId");
CREATE UNIQUE INDEX "org_key_registrations_grantId_key" ON "org_key_registrations"("grantId");
CREATE UNIQUE INDEX "org_key_registrations_jti_key" ON "org_key_registrations"("jti");
