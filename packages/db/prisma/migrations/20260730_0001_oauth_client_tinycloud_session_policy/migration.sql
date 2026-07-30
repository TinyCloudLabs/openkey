ALTER TABLE "oauth_client"
  ADD COLUMN "tinycloudSessionPolicy" TEXT,
  ADD COLUMN "tinycloudSessionOrigin" TEXT;

ALTER TABLE "oauth_client"
  ADD CONSTRAINT "oauth_client_tinycloud_session_policy_complete"
  CHECK (
    ("tinycloudSessionPolicy" IS NULL AND "tinycloudSessionOrigin" IS NULL)
    OR
    ("tinycloudSessionPolicy" IS NOT NULL AND "tinycloudSessionOrigin" IS NOT NULL)
  );
