-- TC-1520: record the fresh-passkey challenge that authorized each org-key signature.
-- Additive only. Nullable: rows written before this migration have no challenge id.
-- No foreign key: consumed challenges are swept, and the audit row must outlive them.

ALTER TABLE "org_key_signature_audits" ADD COLUMN "challengeId" TEXT;
