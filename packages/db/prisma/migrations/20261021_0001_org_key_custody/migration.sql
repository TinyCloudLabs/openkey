-- TC-1518: organization custody for managed keys. Additive only; existing rows keep custody = PERSONAL.

CREATE TYPE "KeyCustody" AS ENUM ('PERSONAL', 'ORG');
CREATE TYPE "KeyGrantRole" AS ENUM ('OWNER', 'ADMIN');

ALTER TABLE "ethereum_keys" ADD COLUMN "custody" "KeyCustody" NOT NULL DEFAULT 'PERSONAL';

-- An ORG key has no personal owner, a per-key seal, and is never the canonical TinyCloud key.
ALTER TABLE "ethereum_keys" ADD CONSTRAINT "ethereum_keys_custody_org_shape_check" CHECK (
    "custody" <> 'ORG'
    OR ("userId" IS NULL AND "keyType" = 'MANAGED' AND "sealingContext" IS NOT NULL AND "isCanonicalTinyCloud" = false)
);

CREATE TABLE "org_keys" (
    "keyId" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "orgName" TEXT NOT NULL,
    "controllerDid" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "org_keys_pkey" PRIMARY KEY ("keyId")
);

CREATE INDEX "org_keys_orgId_idx" ON "org_keys"("orgId");
ALTER TABLE "org_keys" ADD CONSTRAINT "org_keys_keyId_fkey" FOREIGN KEY ("keyId") REFERENCES "ethereum_keys"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE "key_grants" (
    "id" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "role" "KeyGrantRole" NOT NULL,
    "granteeUserId" TEXT,
    "invitedEmail" TEXT,
    "invitedByUserId" TEXT,
    "invitedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "acceptedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "revokedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "key_grants_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "key_grants_keyId_idx" ON "key_grants"("keyId");
CREATE INDEX "key_grants_granteeUserId_idx" ON "key_grants"("granteeUserId");

-- At most one active OWNER per key.
CREATE UNIQUE INDEX "key_grants_one_active_owner_per_key" ON "key_grants"("keyId") WHERE "role" = 'OWNER' AND "revokedAt" IS NULL;

ALTER TABLE "key_grants" ADD CONSTRAINT "key_grants_keyId_fkey" FOREIGN KEY ("keyId") REFERENCES "ethereum_keys"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "key_grants" ADD CONSTRAINT "key_grants_granteeUserId_fkey" FOREIGN KEY ("granteeUserId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- One audit row per org-key signature (K1 D4.6). actorUserId is not a foreign key so history survives account deletion.
CREATE TABLE "org_key_signature_audits" (
    "id" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "grantId" TEXT NOT NULL,
    "actorUserId" TEXT NOT NULL,
    "origin" TEXT NOT NULL,
    "messageDigest" TEXT NOT NULL,
    "passkeyAssertionHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "org_key_signature_audits_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "org_key_signature_audits_keyId_idx" ON "org_key_signature_audits"("keyId");
CREATE INDEX "org_key_signature_audits_grantId_idx" ON "org_key_signature_audits"("grantId");
CREATE UNIQUE INDEX "org_key_signature_audits_passkeyAssertionHash_key" ON "org_key_signature_audits"("passkeyAssertionHash");
ALTER TABLE "org_key_signature_audits" ADD CONSTRAINT "org_key_signature_audits_keyId_fkey" FOREIGN KEY ("keyId") REFERENCES "ethereum_keys"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "org_key_signature_audits" ADD CONSTRAINT "org_key_signature_audits_grantId_fkey" FOREIGN KEY ("grantId") REFERENCES "key_grants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
