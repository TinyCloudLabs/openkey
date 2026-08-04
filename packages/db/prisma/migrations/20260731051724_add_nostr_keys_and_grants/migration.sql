-- CreateTable
CREATE TABLE "nostr_keys" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "label" TEXT,
    "pubkeyHex" TEXT NOT NULL,
    "npub" TEXT NOT NULL,
    "sealedSecret" TEXT NOT NULL,
    "sealingContext" TEXT NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "nostr_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "nostr_signing_grant" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "clientOrigin" TEXT NOT NULL,
    "allowedKinds" INTEGER[],
    "relayUrl" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "nostr_signing_grant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "nostr_signing_decision" (
    "id" TEXT NOT NULL,
    "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT,
    "keyId" TEXT,
    "clientOrigin" TEXT,
    "kind" INTEGER,
    "allowed" BOOLEAN NOT NULL,
    "reasonCode" TEXT NOT NULL,
    "requestDigest" TEXT,
    "tags" JSONB,

    CONSTRAINT "nostr_signing_decision_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "nostr_keys_pubkeyHex_key" ON "nostr_keys"("pubkeyHex");

-- CreateIndex
CREATE UNIQUE INDEX "nostr_keys_npub_key" ON "nostr_keys"("npub");

-- CreateIndex
CREATE UNIQUE INDEX "nostr_keys_sealingContext_key" ON "nostr_keys"("sealingContext");

-- CreateIndex
CREATE INDEX "nostr_keys_userId_idx" ON "nostr_keys"("userId");

-- CreateIndex
CREATE INDEX "nostr_signing_grant_lookup_idx" ON "nostr_signing_grant"("userId", "keyId", "clientOrigin");

-- CreateIndex
CREATE INDEX "nostr_signing_decision_occurredAt_idx" ON "nostr_signing_decision"("occurredAt");

-- CreateIndex
CREATE INDEX "nostr_signing_decision_userId_idx" ON "nostr_signing_decision"("userId");

-- CreateIndex
CREATE INDEX "nostr_signing_decision_keyId_idx" ON "nostr_signing_decision"("keyId");

-- CreateIndex
CREATE INDEX "nostr_signing_decision_allowed_idx" ON "nostr_signing_decision"("allowed");

-- AddForeignKey
ALTER TABLE "nostr_keys" ADD CONSTRAINT "nostr_keys_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "nostr_signing_grant" ADD CONSTRAINT "nostr_signing_grant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "nostr_signing_grant" ADD CONSTRAINT "nostr_signing_grant_keyId_fkey" FOREIGN KEY ("keyId") REFERENCES "nostr_keys"("id") ON DELETE CASCADE ON UPDATE CASCADE;
