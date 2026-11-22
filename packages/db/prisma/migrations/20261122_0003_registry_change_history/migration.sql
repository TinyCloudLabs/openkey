-- TC-3893: store the owner's previous registry location record before publishing a
-- registry change so recent changes can be listed and undone in TinyCloud One.

CREATE TABLE "registry_change_history" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "userId" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "requestingOrigin" TEXT NOT NULL,
  "previousRecord" JSONB NOT NULL,
  "newRecordHash" TEXT NOT NULL,
  "newSequence" INTEGER NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "publishedAt" TIMESTAMP(3),
  CONSTRAINT "registry_change_history_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "registry_change_history_userId_createdAt_idx" ON "registry_change_history" ("userId", "createdAt");
