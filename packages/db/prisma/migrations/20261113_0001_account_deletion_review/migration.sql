CREATE TABLE "account_deletion_review" (
  "id" TEXT NOT NULL,
  "jobId" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "summary" JSONB NOT NULL,
  "actor" TEXT,
  "decidedAt" TIMESTAMP(3),
  "reason" TEXT,
  "disposition" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "account_deletion_review_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "account_deletion_review_jobId_createdAt_idx" ON "account_deletion_review"("jobId", "createdAt");
