-- One account setup the owner asks for on OpenKey's own page (/widget/account-setup). Single use: bound to the user,
-- the session, the key and the exact record text OpenKey built ("payload", "payloadDigest"); five minutes to approve.
-- A new table: no existing row is read or locked.
CREATE TABLE "account_setup_request" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "chainId" INTEGER NOT NULL,
    "requestOrigin" TEXT,
    "placement" TEXT NOT NULL,
    "nodeUrl" TEXT NOT NULL,
    "nodeDid" TEXT NOT NULL,
    "payload" TEXT NOT NULL,
    "payloadDigest" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "approvingAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "supersededAt" TIMESTAMP(3),
    "publishingAt" TIMESTAMP(3),
    "outcome" TEXT,
    "failureCode" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "account_setup_request_pkey" PRIMARY KEY ("id"),
    -- The record's owner subject is on chain 1, whatever chain an app signs in on.
    CONSTRAINT "account_setup_request_chain_check" CHECK ("chainId" = 1),
    -- TinyCloud hosting is the one placement OpenKey sets up.
    CONSTRAINT "account_setup_request_placement_check" CHECK ("placement" IN ('tinycloud')),
    CONSTRAINT "account_setup_request_outcome_check" CHECK ("outcome" IS NULL OR "outcome" IN ('pending', 'published', 'present', 'failed'))
);

CREATE INDEX "account_setup_request_userId_keyId_idx" ON "account_setup_request"("userId", "keyId");
CREATE INDEX "account_setup_request_sessionId_idx" ON "account_setup_request"("sessionId");
CREATE INDEX "account_setup_request_keyId_idx" ON "account_setup_request"("keyId");
CREATE INDEX "account_setup_request_expiresAt_idx" ON "account_setup_request"("expiresAt");

ALTER TABLE "account_setup_request" ADD CONSTRAINT "account_setup_request_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "account_setup_request" ADD CONSTRAINT "account_setup_request_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "account_setup_request" ADD CONSTRAINT "account_setup_request_keyId_fkey" FOREIGN KEY ("keyId") REFERENCES "ethereum_keys"("id") ON DELETE CASCADE ON UPDATE CASCADE;
