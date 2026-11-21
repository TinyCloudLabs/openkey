-- TC-3657: Prisma-backed stores for the outside-app one-tap TinyCloud setup endpoint.
--
-- Two tables:
--   tinycloud_setup_consumed_nonce: single-use proof that a setup ticket's server-minted
--     nonce has been consumed. A new ticket's consume() refuses when a row with the
--     ticket's nonce already exists, so a replayed ticket cannot sign a second record
--     even after a restart or across API replicas (C1).
--   tinycloud_setup_rate_limit_bucket: per-owner-per-action window counter with atomic
--     increment via ON CONFLICT ... DO UPDATE. One shared row per (action, subject,
--     windowStartMs) across every API replica, so the server-side per-owner limit is
--     global, not per-process.

CREATE TABLE "tinycloud_setup_consumed_nonce" (
  "nonce" TEXT NOT NULL PRIMARY KEY,
  "subject" TEXT NOT NULL,
  "mintedAt" TIMESTAMP(3) NOT NULL,
  "consumedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "tinycloud_setup_consumed_nonce_minted_at" ON "tinycloud_setup_consumed_nonce" ("mintedAt");

CREATE TABLE "tinycloud_setup_rate_limit_bucket" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "action" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "windowStartMs" BIGINT NOT NULL,
  "count" INTEGER NOT NULL DEFAULT 0,
  "updatedAt" TIMESTAMP(3) NOT NULL
);
CREATE INDEX "tinycloud_setup_rate_limit_bucket_window" ON "tinycloud_setup_rate_limit_bucket" ("windowStartMs");
