ALTER TABLE "approval_request" ADD COLUMN "deniedAt" TIMESTAMP(3);

ALTER TABLE "approval_request" DROP CONSTRAINT "approval_request_result_state";
ALTER TABLE "approval_request" ADD CONSTRAINT "approval_request_result_state" CHECK (
  ("resultRef" IS NULL AND "approvedByUserId" IS NULL AND "ownerDid" IS NULL
   AND "encryptedResult" IS NULL AND "delegationExpiresAt" IS NULL AND "resultExpiresAt" IS NULL
   AND "ackId" IS NULL AND "acknowledgedAt" IS NULL)
  OR
  ("resultRef" IS NOT NULL AND "approvedByUserId" IS NOT NULL AND "ownerDid" IS NOT NULL
   AND "deniedAt" IS NULL
   AND "delegationExpiresAt" IS NOT NULL AND "resultExpiresAt" IS NOT NULL
   AND "resultExpiresAt" <= "delegationExpiresAt"
   AND (("ackId" IS NULL AND "acknowledgedAt" IS NULL AND "encryptedResult" IS NOT NULL)
     OR ("ackId" IS NOT NULL AND "acknowledgedAt" IS NOT NULL AND "encryptedResult" IS NULL)))
);
