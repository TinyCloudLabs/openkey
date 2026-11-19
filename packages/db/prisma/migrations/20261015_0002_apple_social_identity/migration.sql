ALTER TABLE "account" ADD COLUMN "appleClientId" TEXT;
ALTER TABLE "user" ADD COLUMN "socialCreatedProvider" TEXT,
                   ADD COLUMN "socialEmailReviewedAt" TIMESTAMP(3),
                   ADD COLUMN "lockedAt" TIMESTAMP(3);
