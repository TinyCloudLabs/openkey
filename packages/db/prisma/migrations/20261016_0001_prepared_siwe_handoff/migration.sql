CREATE TABLE "prepared_handoff" (
    "ticketHash" TEXT NOT NULL,
    "cancelSecretHash" TEXT NOT NULL,
    "request" JSONB NOT NULL,
    "callback" TEXT,
    "state" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "requestedAt" TIMESTAMP(3) NOT NULL,
    "requestIpHash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "ownerId" TEXT,
    "contextTokenHash" TEXT,
    "selectedKeyId" TEXT,
    CONSTRAINT "prepared_handoff_pkey" PRIMARY KEY ("ticketHash")
);

CREATE UNIQUE INDEX "prepared_handoff_contextTokenHash_key" ON "prepared_handoff"("contextTokenHash");
CREATE INDEX "prepared_handoff_requestIpHash_requestedAt_idx" ON "prepared_handoff"("requestIpHash", "requestedAt");
CREATE INDEX "prepared_handoff_expiresAt_idx" ON "prepared_handoff"("expiresAt");
ALTER TABLE "prepared_handoff" ADD CONSTRAINT "prepared_handoff_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
