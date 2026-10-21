-- TC-1520 K4: the issuer-statement (kind 1) binding fields. slug and issuerDid are
-- the org record values a statement must name. origin is the requesting origin
-- recorded on each signing challenge. Additive only, all nullable. A key with a
-- NULL slug or issuerDid refuses every issuer statement, and a challenge with a
-- NULL origin cannot sign.

ALTER TABLE "org_keys" ADD COLUMN "slug" TEXT,
ADD COLUMN "issuerDid" TEXT;

ALTER TABLE "org_key_sign_challenges" ADD COLUMN "origin" TEXT;
