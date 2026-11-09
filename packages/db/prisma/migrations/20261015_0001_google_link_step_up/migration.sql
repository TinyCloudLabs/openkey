BEGIN;

ALTER TABLE "session" ADD COLUMN "lastEmailOtpAt" TIMESTAMP(3);

CREATE UNIQUE INDEX "account_providerId_accountId_key" ON "account"("providerId", "accountId");

COMMIT;
