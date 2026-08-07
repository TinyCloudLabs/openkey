-- Nostr custody capability model v2: grants can now authorize named crypto
-- operations (nip44_encrypt / nip44_decrypt / nip59_wrap / nip59_unwrap)
-- alongside signable event kinds, and audit decisions record which named
-- operation (if any) a decision was about.

-- AlterTable
ALTER TABLE "nostr_signing_grant" ADD COLUMN "allowedOperations" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

-- AlterTable
ALTER TABLE "nostr_signing_decision" ADD COLUMN "operation" TEXT;
