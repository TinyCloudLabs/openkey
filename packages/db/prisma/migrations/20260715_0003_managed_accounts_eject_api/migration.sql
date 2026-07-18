CREATE TYPE "EjectRequestStatus" AS ENUM ('PENDING', 'COMPLETED', 'FAILED');

ALTER TABLE "managed_account"
  ADD COLUMN "tenantParentDelegation" JSONB,
  ADD COLUMN "tenantParentExpiresAt" TIMESTAMP(3),
  ADD COLUMN "brokerAccessDisabledAt" TIMESTAMP(3);

CREATE TABLE "eject_request" (
  "id" TEXT NOT NULL,
  "managedAccountId" TEXT NOT NULL,
  "ownerUserId" TEXT NOT NULL,
  "idempotencyKey" TEXT NOT NULL,
  "expectedEpoch" INTEGER NOT NULL,
  "status" "EjectRequestStatus" NOT NULL DEFAULT 'PENDING',
  "result" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "completedAt" TIMESTAMP(3),
  CONSTRAINT "eject_request_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "eject_request_account_fkey" FOREIGN KEY ("managedAccountId") REFERENCES "managed_account"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "eject_request_owner_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "eject_request_account_owner_idempotency_key"
  ON "eject_request"("managedAccountId", "ownerUserId", "idempotencyKey");
CREATE INDEX "eject_request_account_status_idx"
  ON "eject_request"("managedAccountId", "status");

CREATE OR REPLACE FUNCTION openkey_eject_request_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."id" IS DISTINCT FROM OLD."id"
     OR NEW."managedAccountId" IS DISTINCT FROM OLD."managedAccountId"
     OR NEW."ownerUserId" IS DISTINCT FROM OLD."ownerUserId"
     OR NEW."idempotencyKey" IS DISTINCT FROM OLD."idempotencyKey"
     OR NEW."expectedEpoch" IS DISTINCT FROM OLD."expectedEpoch"
     OR NEW."createdAt" IS DISTINCT FROM OLD."createdAt" THEN
    RAISE EXCEPTION 'eject request identity is immutable';
  END IF;
  IF OLD."status" = 'COMPLETED' AND (NEW."status" IS DISTINCT FROM OLD."status" OR NEW."result" IS DISTINCT FROM OLD."result") THEN
    RAISE EXCEPTION 'completed eject request is immutable';
  END IF;
  IF NEW."status" = 'COMPLETED' AND (NEW."result" IS NULL OR NEW."completedAt" IS NULL) THEN
    RAISE EXCEPTION 'completed eject request requires durable result';
  END IF;
  IF OLD."completedAt" IS NOT NULL AND NEW."completedAt" IS DISTINCT FROM OLD."completedAt" THEN
    RAISE EXCEPTION 'eject completion timestamp is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER eject_request_guard BEFORE UPDATE ON "eject_request"
  FOR EACH ROW EXECUTE FUNCTION openkey_eject_request_guard();
