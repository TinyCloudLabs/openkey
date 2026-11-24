-- TC-3569: a native request is either a sign-in (the existing flow) or a
-- step-up on an existing grant. Additive: existing rows take kind 'SIGNIN'
-- with no grant and no app; nothing writes a STEPUP row until the step-up
-- endpoint ships.
ALTER TABLE "tinycloud_native_request"
  ADD COLUMN "kind" TEXT NOT NULL DEFAULT 'SIGNIN',
  ADD COLUMN "grantId" TEXT,
  ADD COLUMN "appId" TEXT,
  ADD CONSTRAINT "tinycloud_native_request_kind_check" CHECK (
    ("kind" = 'SIGNIN' AND "grantId" IS NULL AND "appId" IS NULL)
    OR ("kind" = 'STEPUP' AND "grantId" IS NOT NULL AND "appId" IS NOT NULL)
  ),
  ADD CONSTRAINT "tinycloud_native_request_grantId_fkey"
    FOREIGN KEY ("grantId") REFERENCES "tinycloud_native_grant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE INDEX "tinycloud_native_request_grantId_idx" ON "tinycloud_native_request"("grantId");
