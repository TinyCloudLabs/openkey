CREATE TABLE "escrow_archive" (
  "escrowId" TEXT PRIMARY KEY,
  "headerHash" TEXT NOT NULL UNIQUE,
  "bundle" JSONB NOT NULL,
  "recordManifestUtf8" TEXT NOT NULL,
  "dbSnapshotUtf8" TEXT NOT NULL,
  "sourceSnapshotId" TEXT NOT NULL,
  "exportSnapshotId" TEXT NOT NULL,
  "expectedRecords" INTEGER NOT NULL,
  "completedRecords" INTEGER NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "escrow_archive_complete" CHECK ("expectedRecords" >= 0 AND "expectedRecords" = "completedRecords")
);
