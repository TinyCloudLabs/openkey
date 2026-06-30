-- CreateTable
CREATE TABLE "tinycloud_bootstrap_state" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "chainId" INTEGER NOT NULL,
    "tinycloudHost" TEXT NOT NULL,
    "bootstrapVersion" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "attemptId" TEXT,
    "lockExpiresAt" TIMESTAMP(3),
    "checkedAt" TIMESTAMP(3) NOT NULL,
    "completedAt" TIMESTAMP(3),
    "failureCode" TEXT,
    "failureReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tinycloud_bootstrap_state_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "tinycloud_bootstrap_state_keyId_chainId_tinycloudHost_bootstrapVersion_key" ON "tinycloud_bootstrap_state"("keyId", "chainId", "tinycloudHost", "bootstrapVersion");

-- CreateIndex
CREATE INDEX "tinycloud_bootstrap_state_userId_idx" ON "tinycloud_bootstrap_state"("userId");

-- CreateIndex
CREATE INDEX "tinycloud_bootstrap_state_status_idx" ON "tinycloud_bootstrap_state"("status");

-- AddForeignKey
ALTER TABLE "tinycloud_bootstrap_state" ADD CONSTRAINT "tinycloud_bootstrap_state_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tinycloud_bootstrap_state" ADD CONSTRAINT "tinycloud_bootstrap_state_keyId_fkey" FOREIGN KEY ("keyId") REFERENCES "ethereum_keys"("id") ON DELETE CASCADE ON UPDATE CASCADE;
