-- TC-3903: the deletion audit survives the account it records. One row per ethereum address the deleted
-- account held; didHash is SHA-256 (hex) of the lowercase did:pkh:eip155:1:<address>. No user id, email,
-- address or IP, and no foreign key to "user": the cascade must not take these rows.
CREATE TABLE "account_deletion_audit" (
    "id" TEXT NOT NULL,
    "deletedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "didHash" TEXT NOT NULL,

    CONSTRAINT "account_deletion_audit_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "account_deletion_audit_didHash_idx" ON "account_deletion_audit"("didHash");
