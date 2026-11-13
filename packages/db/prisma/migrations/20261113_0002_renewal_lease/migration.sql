-- TC-2933: one row per owner renewal lease the node admitted for an approval request, written in the same
-- transaction as the approval, so the owner can see and stop it later (TC-2946 sets "revokedAt").
CREATE TABLE "renewal_lease" (
    "leaseCid" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT,
    "approvalRequestId" TEXT NOT NULL,
    "ownerDid" TEXT NOT NULL,
    "originalCid" TEXT NOT NULL,
    "nodeOrigin" TEXT NOT NULL,
    "nodeDid" TEXT NOT NULL,
    "renewerDid" TEXT NOT NULL,
    "leaseLifetimeSeconds" INTEGER NOT NULL,
    "approvedAt" TIMESTAMP(3) NOT NULL,
    "leaseExpiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "renewal_lease_pkey" PRIMARY KEY ("leaseCid")
);

CREATE UNIQUE INDEX "renewal_lease_approvalRequestId_key" ON "renewal_lease"("approvalRequestId");
CREATE INDEX "renewal_lease_userId_idx" ON "renewal_lease"("userId");
CREATE INDEX "renewal_lease_sessionId_idx" ON "renewal_lease"("sessionId");

ALTER TABLE "renewal_lease" ADD CONSTRAINT "renewal_lease_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
