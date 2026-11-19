-- TC-2933: the owner's renewal lease steps for an approval request, saved before each node call
-- so a retry reuses the same grant and lease instead of signing new ones.
ALTER TABLE "approval_request" ADD COLUMN "renewal" JSONB;
