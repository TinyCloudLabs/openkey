-- TC-3353: one row per deleted account, written in the same transaction that deletes the account's keys.
-- "ownerDigests" holds the SHA-256 (hex) of each deleted key's did:pkh:eip155:1:<address>. The row has no
-- user id, email or address and no foreign key to "user".
CREATE TABLE "account_deletion_receipt" (
    "id" TEXT NOT NULL,
    "deletedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ownerDigests" TEXT[],

    CONSTRAINT "account_deletion_receipt_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "account_deletion_receipt_deletedAt_idx" ON "account_deletion_receipt"("deletedAt");

-- Append-only: a receipt is never rewritten or removed. There is no foreign key to cascade from, so every
-- row-level UPDATE and DELETE is refused. TRUNCATE is not covered.
CREATE FUNCTION refuse_account_deletion_receipt_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'account deletion receipt is append-only';
END $$;
CREATE TRIGGER account_deletion_receipt_append_only BEFORE UPDATE OR DELETE ON "account_deletion_receipt"
  FOR EACH ROW EXECUTE FUNCTION refuse_account_deletion_receipt_change();
