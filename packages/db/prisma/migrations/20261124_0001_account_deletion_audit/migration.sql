-- TC-3903: the deletion audit survives the account it records. One row per deletion. No identifier of
-- any kind — an unkeyed hash of a public address is still identifying — so the row holds only that a
-- delete happened, whether billing was settled for it, and whether any subscription was cancelled.
CREATE TABLE "account_deletion_audit" (
    "id" TEXT NOT NULL,
    "deletedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "hadSubscription" BOOLEAN NOT NULL,
    "billingOk" BOOLEAN NOT NULL,

    CONSTRAINT "account_deletion_audit_pkey" PRIMARY KEY ("id")
);
