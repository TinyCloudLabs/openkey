ALTER TABLE "account_deletion_review" ADD COLUMN "eventKey" TEXT;
ALTER TABLE "account_deletion_review" ADD COLUMN "deliveredAt" TIMESTAMP(3);
ALTER TABLE "account_deletion_review" ADD COLUMN "expiresAt" TIMESTAMP(3);
CREATE UNIQUE INDEX "account_deletion_review_eventKey_key" ON "account_deletion_review"("eventKey");
