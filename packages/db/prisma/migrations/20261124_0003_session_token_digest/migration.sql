-- Session tokens are stored as a SHA-256 digest from this release on. Every existing row holds the token itself, so
-- every session ends: people sign in once and AI connectors reconnect. Data-only apart from the constraint below.
DELETE FROM "session";

-- The migration runs before the new API image starts, so the previous image can still sign people in. The constraint
-- admits only a lowercase 64-character hex digest: a sign-in by the previous image fails and stores nothing, so no
-- plaintext token exists for a rollback or a failed cutover to make live. The table is empty here, so validation is
-- immediate.
ALTER TABLE "session" ADD CONSTRAINT "session_token_digest_check" CHECK ("token" ~ '^[0-9a-f]{64}$');
