-- Session tokens are stored as a SHA-256 digest from this release on. Every existing row holds the token itself, so
-- every session ends: people sign in once and AI connectors reconnect. Data-only; no column changes.
DELETE FROM "session";
