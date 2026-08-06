-- TC-485 / TC-486 expand step: one OpenKey-owned canonical managed
-- TinyCloud identity per user. Historical personal keys remain intact.
ALTER TABLE "ethereum_keys"
  ADD COLUMN "isCanonicalTinyCloud" BOOLEAN NOT NULL DEFAULT false;

-- Existing users retain their first active managed personal key. The complete
-- ordering is deterministic for equal keyIndex values and preserves the key's
-- address, sealed blob, and therefore existing TinyCloud data.
WITH ranked_personal_keys AS (
  SELECT "id", row_number() OVER (
    PARTITION BY "userId"
    ORDER BY "keyIndex" ASC, "createdAt" ASC, "id" ASC
  ) AS position
  FROM "ethereum_keys"
  WHERE "userId" IS NOT NULL
    AND "keyPurpose" = 'PERSONAL'
    AND "keyType" = 'MANAGED'
    AND "archivedAt" IS NULL
)
UPDATE "ethereum_keys" AS key
SET "isCanonicalTinyCloud" = true
FROM ranked_personal_keys AS ranked
WHERE key."id" = ranked."id" AND ranked.position = 1;

CREATE UNIQUE INDEX "ethereum_keys_one_active_canonical_tinycloud_key"
  ON "ethereum_keys" ("userId")
  WHERE "isCanonicalTinyCloud" = true
    AND "userId" IS NOT NULL
    AND "keyPurpose" = 'PERSONAL'
    AND "keyType" = 'MANAGED'
    AND "archivedAt" IS NULL;
