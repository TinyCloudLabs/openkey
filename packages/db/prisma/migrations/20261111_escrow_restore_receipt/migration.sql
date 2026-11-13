CREATE TABLE "escrow_restore_receipt" (
  "escrowId" TEXT PRIMARY KEY,
  "headerHash" TEXT NOT NULL,
  "descriptorHash" TEXT NOT NULL,
  "newPolicyId" TEXT NOT NULL,
  "targetAppId" TEXT NOT NULL,
  "targetComposeHash" TEXT NOT NULL,
  "completedRecords" INTEGER NOT NULL CHECK ("completedRecords" >= 0),
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
