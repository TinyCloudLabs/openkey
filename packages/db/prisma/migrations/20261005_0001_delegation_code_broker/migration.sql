CREATE TABLE "delegation_code" (
    "code" TEXT NOT NULL,
    "delegation" JSONB NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "delegation_code_pkey" PRIMARY KEY ("code")
);

CREATE INDEX "delegation_code_expiresAt_idx" ON "delegation_code"("expiresAt");
