-- TC-1518 K2a: single-use server nonces for org-key signing challenges, and the
-- grant role and message kind recorded on each org-key signature audit row.
-- Additive only. Audit rows are written only by signing, which refuses every
-- message kind until K4 defines the signable kinds, so the table is empty.

ALTER TABLE "org_key_signature_audits" ADD COLUMN "role" "KeyGrantRole" NOT NULL,
ADD COLUMN "messageKind" TEXT NOT NULL;

-- One row per issued fresh-passkey challenge. The nonce is server-generated and
-- single-use: signing marks consumedAt in the signing transaction, so a passkey
-- assertion over this challenge signs at most once.
CREATE TABLE "org_key_sign_challenges" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "grantId" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "messageDigest" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "org_key_sign_challenges_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "org_key_sign_challenges_nonce_key" ON "org_key_sign_challenges"("nonce");
CREATE INDEX "org_key_sign_challenges_userId_idx" ON "org_key_sign_challenges"("userId");
CREATE INDEX "org_key_sign_challenges_keyId_idx" ON "org_key_sign_challenges"("keyId");
CREATE INDEX "org_key_sign_challenges_grantId_idx" ON "org_key_sign_challenges"("grantId");

-- Challenges are ephemeral and carry no audit meaning, so deleting the user removes them.
ALTER TABLE "org_key_sign_challenges" ADD CONSTRAINT "org_key_sign_challenges_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "org_key_sign_challenges" ADD CONSTRAINT "org_key_sign_challenges_keyId_fkey" FOREIGN KEY ("keyId") REFERENCES "ethereum_keys"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "org_key_sign_challenges" ADD CONSTRAINT "org_key_sign_challenges_grantId_fkey" FOREIGN KEY ("grantId") REFERENCES "key_grants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
