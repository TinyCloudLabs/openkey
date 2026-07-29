CREATE TABLE "coordinationos_signing_decision" (
  "id" TEXT NOT NULL,
  "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "policyVersion" TEXT NOT NULL,
  "decision" TEXT NOT NULL,
  "reasonCode" TEXT NOT NULL,
  "requestId" TEXT,
  "oauthAccessTokenId" TEXT,
  "tokenDigest" TEXT,
  "clientId" TEXT,
  "userId" TEXT,
  "keyId" TEXT,
  "origin" TEXT,
  "chainId" INTEGER,
  "purpose" TEXT,
  "type" TEXT,
  "siweDigest" TEXT,
  "capabilityDigest" TEXT,
  "nonceDigest" TEXT,
  "issuedAt" TEXT,
  "expirationTime" TEXT,
  "sessionTtlSeconds" INTEGER,
  "evidence" JSONB NOT NULL,
  CONSTRAINT "coordinationos_signing_decision_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "coordinationos_session_grant" (
  "id" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "oauthAccessTokenId" TEXT NOT NULL,
  "nonceDigest" TEXT NOT NULL,
  "clientId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "keyId" TEXT NOT NULL,
  "decisionId" TEXT NOT NULL,
  CONSTRAINT "coordinationos_session_grant_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "coordinationos_session_grant_oauthAccessTokenId_key"
  ON "coordinationos_session_grant"("oauthAccessTokenId");
CREATE UNIQUE INDEX "coordinationos_session_grant_nonceDigest_key"
  ON "coordinationos_session_grant"("nonceDigest");
CREATE UNIQUE INDEX "coordinationos_session_grant_decisionId_key"
  ON "coordinationos_session_grant"("decisionId");
CREATE INDEX "coordinationos_session_grant_clientId_idx"
  ON "coordinationos_session_grant"("clientId");
CREATE INDEX "coordinationos_session_grant_userId_idx"
  ON "coordinationos_session_grant"("userId");
CREATE INDEX "coordinationos_session_grant_keyId_idx"
  ON "coordinationos_session_grant"("keyId");

CREATE INDEX "coordinationos_signing_decision_occurredAt_idx"
  ON "coordinationos_signing_decision"("occurredAt");
CREATE INDEX "coordinationos_signing_decision_decision_idx"
  ON "coordinationos_signing_decision"("decision");
CREATE INDEX "coordinationos_signing_decision_reasonCode_idx"
  ON "coordinationos_signing_decision"("reasonCode");
CREATE INDEX "coordinationos_signing_decision_clientId_idx"
  ON "coordinationos_signing_decision"("clientId");
CREATE INDEX "coordinationos_signing_decision_userId_idx"
  ON "coordinationos_signing_decision"("userId");
CREATE INDEX "coordinationos_signing_decision_keyId_idx"
  ON "coordinationos_signing_decision"("keyId");
