CREATE TABLE "account_deletion_job" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "state" TEXT NOT NULL DEFAULT 'deletion_requested',
  "progress" JSONB NOT NULL,
  "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "account_deletion_job_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "account_deletion_job_userId_key" ON "account_deletion_job"("userId");
CREATE INDEX "account_deletion_job_state_nextAttemptAt_idx" ON "account_deletion_job"("state", "nextAttemptAt");
