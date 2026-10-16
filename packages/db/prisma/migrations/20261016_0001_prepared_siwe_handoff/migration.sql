CREATE TABLE "prepared_handoff" (
    "ticketHash" TEXT NOT NULL,
    "cancelSecretHash" TEXT NOT NULL,
    "nonceHash" TEXT NOT NULL,
    "request" JSONB NOT NULL,
    "callback" TEXT,
    "state" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "requestedAt" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "ownerId" TEXT NOT NULL,
    "contextTokenHash" TEXT,
    "selectedKeyId" TEXT,
    CONSTRAINT "prepared_handoff_pkey" PRIMARY KEY ("ticketHash")
);

CREATE UNIQUE INDEX "prepared_handoff_contextTokenHash_key" ON "prepared_handoff"("contextTokenHash");
CREATE UNIQUE INDEX "prepared_handoff_ownerId_nonceHash_key" ON "prepared_handoff"("ownerId", "nonceHash");
CREATE INDEX "prepared_handoff_ownerId_requestedAt_idx" ON "prepared_handoff"("ownerId", "requestedAt");
CREATE INDEX "prepared_handoff_expiresAt_idx" ON "prepared_handoff"("expiresAt");
ALTER TABLE "prepared_handoff" ADD CONSTRAINT "prepared_handoff_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
