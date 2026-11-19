CREATE TABLE "apple_social_continuation" (
    "id" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "apple_social_continuation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "apple_social_continuation_identifier_key" ON "apple_social_continuation"("identifier");
CREATE INDEX "apple_social_continuation_expiresAt_idx" ON "apple_social_continuation"("expiresAt");
