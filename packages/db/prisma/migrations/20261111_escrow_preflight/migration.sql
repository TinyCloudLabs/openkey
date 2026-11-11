CREATE TABLE "escrow_preflight" (
  "policyHash" TEXT PRIMARY KEY,
  "nonce" TEXT NOT NULL UNIQUE,
  "expiresAt" TIMESTAMPTZ NOT NULL,
  "payload" JSONB NOT NULL,
  "consumedAt" TIMESTAMPTZ
);
