CREATE TABLE "escrow_authorization" (
  "nonce" TEXT PRIMARY KEY,
  "policyHash" TEXT NOT NULL,
  "dryRun" BOOLEAN NOT NULL,
  "operatorId" TEXT NOT NULL,
  "approverId" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "escrow_distinct_people" CHECK ("operatorId" <> "approverId")
);
CREATE INDEX "escrow_authorization_createdAt_idx" ON "escrow_authorization" ("createdAt");
