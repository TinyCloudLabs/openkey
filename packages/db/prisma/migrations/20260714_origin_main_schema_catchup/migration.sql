-- Catch up the historical baseline to the schema that was deployed from
-- origin/main before the managed-account migration. This migration is kept
-- separate so an already-applied 0_init is never silently rewritten.

CREATE TYPE "KeyType" AS ENUM ('MANAGED', 'EXTERNAL');
CREATE TYPE "Plan" AS ENUM ('FREE', 'PRO', 'SCALE', 'ENTERPRISE');
CREATE TYPE "BillingState" AS ENUM ('FREE', 'ACTIVE', 'PAST_DUE', 'CANCELLED');

ALTER TABLE "ethereum_keys"
  ALTER COLUMN "sealedBlob" DROP NOT NULL;
ALTER TABLE "ethereum_keys"
  ADD COLUMN "keyType" "KeyType" NOT NULL DEFAULT 'MANAGED';

CREATE TABLE "developer_account" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "stripeCustomerId" TEXT,
    "plan" "Plan" NOT NULL DEFAULT 'FREE',
    "billingState" "BillingState" NOT NULL DEFAULT 'FREE',
    "mauLimit" INTEGER NOT NULL DEFAULT 1000,
    "appLimit" INTEGER NOT NULL DEFAULT 3,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "stripeSubscriptionId" TEXT,
    CONSTRAINT "developer_account_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "developer_account_userId_key" ON "developer_account"("userId");
CREATE UNIQUE INDEX "developer_account_stripeCustomerId_key" ON "developer_account"("stripeCustomerId");
ALTER TABLE "developer_account" ADD CONSTRAINT "developer_account_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "oauth_daily_stats" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "date" DATE NOT NULL,
    "uniqueUsers" INTEGER NOT NULL DEFAULT 0,
    "totalAuthorizations" INTEGER NOT NULL DEFAULT 0,
    "totalTokenExchanges" INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "oauth_daily_stats_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "oauth_daily_stats_clientId_date_key" ON "oauth_daily_stats"("clientId", "date");
CREATE INDEX "oauth_daily_stats_clientId_idx" ON "oauth_daily_stats"("clientId");
