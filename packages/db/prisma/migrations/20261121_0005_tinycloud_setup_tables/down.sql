-- TC-3657: rollback for the OpenKey outside-app setup Prisma stores. Drops the two
-- tables introduced by the companion migration.sql. Safe only when the setup endpoint is
-- not serving traffic (unset `OPENKEY_SETUP_TICKET_SECRET` or stop the API first);
-- Bobbie's C1 single-use invariant and C5 per-owner rate limit depend on these tables.
-- Parity with the TC-3569 S1b migrations, each of which ships a matching `down.sql`.

DROP INDEX IF EXISTS "tinycloud_setup_rate_limit_bucket_window";
DROP TABLE IF EXISTS "tinycloud_setup_rate_limit_bucket";
DROP INDEX IF EXISTS "tinycloud_setup_consumed_nonce_minted_at";
DROP TABLE IF EXISTS "tinycloud_setup_consumed_nonce";
