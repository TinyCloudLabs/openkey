CREATE TABLE "device_authorization" (
    "id" TEXT NOT NULL,
    "userCode" TEXT NOT NULL,
    "deviceSecretHash" TEXT NOT NULL,
    "codeChallenge" TEXT NOT NULL,
    "sessionDid" TEXT NOT NULL,
    "publicJwk" JSONB NOT NULL,
    "relayPublicJwk" JSONB NOT NULL,
    "permissions" JSONB NOT NULL,
    "nodeOrigin" TEXT NOT NULL,
    "shareOrigin" TEXT NOT NULL,
    "delegationExpiresAt" TIMESTAMP(3) NOT NULL,
    "transactionExpiresAt" TIMESTAMP(3) NOT NULL,
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "requestIpHash" TEXT NOT NULL,
    "nextPollAt" TIMESTAMP(3) NOT NULL,
    "pollIntervalSeconds" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "approvedByUserId" TEXT,
    "encryptedResult" TEXT,
    "consumedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "device_authorization_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "device_authorization_userCode_key" ON "device_authorization"("userCode");
CREATE INDEX "device_authorization_requestIpHash_requestedAt_idx" ON "device_authorization"("requestIpHash", "requestedAt");
CREATE INDEX "device_authorization_status_transactionExpiresAt_idx" ON "device_authorization"("status", "transactionExpiresAt");

ALTER TABLE "device_authorization"
ADD CONSTRAINT "device_authorization_approvedByUserId_fkey"
FOREIGN KEY ("approvedByUserId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;
