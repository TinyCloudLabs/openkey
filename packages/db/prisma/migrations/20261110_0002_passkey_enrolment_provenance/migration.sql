-- TC-1198: passkey enrolment provenance (plan TC-1188 §2, §3).
-- A passkey counts for step-up only when its enrolment was authorized by
-- account creation or a fresh step-up. New rows default to false, so a stock
-- Better Auth write that bypasses OpenKey's hooks never counts.
ALTER TABLE "passkey" ADD COLUMN "enrolledVia" TEXT,
                      ADD COLUMN "enrolledStepUpAt" TIMESTAMP(3),
                      ADD COLUMN "countsForStepUp" BOOLEAN NOT NULL DEFAULT false;

-- Every passkey enrolled before this change keeps today's step-up authority
-- (the owner's status quo); no existing user loses passkey deletion.
UPDATE "passkey" SET "countsForStepUp" = true, "enrolledVia" = 'legacy';

-- The credential behind a session's passkey freshness. Step-up checks that
-- this passkey still exists and counts, not only that lastPasskeyAt is fresh.
ALTER TABLE "session" ADD COLUMN "lastPasskeyId" TEXT;
