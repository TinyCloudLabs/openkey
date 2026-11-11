CREATE TABLE "escrow_authorization" (
  "nonce" TEXT PRIMARY KEY,
  "policyHash" TEXT NOT NULL,
  "dryRun" BOOLEAN NOT NULL,
  "operatorId" TEXT NOT NULL,
  "approverId" TEXT,
  "kind" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "escrow_distinct_people" CHECK (
    ("kind" = 'preflight' AND "approverId" IS NULL AND "dryRun" = true)
    OR ("kind" = 'export' AND "approverId" IS NOT NULL AND "operatorId" <> "approverId")
  )
);
CREATE INDEX "escrow_authorization_createdAt_idx" ON "escrow_authorization" ("createdAt");
