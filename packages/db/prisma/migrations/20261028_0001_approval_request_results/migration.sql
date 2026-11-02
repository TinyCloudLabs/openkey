CREATE TABLE "approval_request" (
    "id" TEXT NOT NULL,
    "bodyCid" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "request" JSONB NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resultRef" TEXT,
    "approvedByUserId" TEXT,
    "ownerDid" TEXT,
    "encryptedResult" TEXT,
    "delegationExpiresAt" TIMESTAMP(3),
    "resultExpiresAt" TIMESTAMP(3),
    "ackId" TEXT,
    "acknowledgedAt" TIMESTAMP(3),
    CONSTRAINT "approval_request_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "approval_request_result_state" CHECK (
      ("resultRef" IS NULL AND "approvedByUserId" IS NULL AND "ownerDid" IS NULL
       AND "encryptedResult" IS NULL AND "delegationExpiresAt" IS NULL AND "resultExpiresAt" IS NULL
       AND "ackId" IS NULL AND "acknowledgedAt" IS NULL)
      OR
      ("resultRef" IS NOT NULL AND "approvedByUserId" IS NOT NULL AND "ownerDid" IS NOT NULL
       AND "delegationExpiresAt" IS NOT NULL AND "resultExpiresAt" IS NOT NULL
       AND "resultExpiresAt" <= "delegationExpiresAt"
       AND (("ackId" IS NULL AND "acknowledgedAt" IS NULL AND "encryptedResult" IS NOT NULL)
         OR ("ackId" IS NOT NULL AND "acknowledgedAt" IS NOT NULL AND "encryptedResult" IS NULL)))
    )
);
CREATE UNIQUE INDEX "approval_request_resultRef_key" ON "approval_request"("resultRef");
CREATE INDEX "approval_request_expiresAt_idx" ON "approval_request"("expiresAt");
CREATE INDEX "approval_request_resultExpiresAt_idx" ON "approval_request"("resultExpiresAt");
