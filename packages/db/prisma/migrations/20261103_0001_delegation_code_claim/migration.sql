CREATE TABLE "delegation_code_claim" (
    "code" TEXT NOT NULL,
    "claimHash" TEXT NOT NULL,
    "delegation" JSONB,
    "redeemedAt" TIMESTAMP(3) NOT NULL,
    "acknowledgedAt" TIMESTAMP(3),

    CONSTRAINT "delegation_code_claim_pkey" PRIMARY KEY ("code"),
    CONSTRAINT "delegation_code_claim_ack_state" CHECK (("acknowledgedAt" IS NULL) = ("delegation" IS NOT NULL))
);

CREATE INDEX "delegation_code_claim_redeemedAt_idx" ON "delegation_code_claim"("redeemedAt");
