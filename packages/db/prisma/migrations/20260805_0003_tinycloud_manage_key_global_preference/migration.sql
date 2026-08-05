-- TC-484: TinyCloud OAuth signing is independent from the pre-existing
-- bootstrap Auto-Sign allowlist. Existing users keep signing enabled unless
-- they explicitly turn off this new, narrower capability.
ALTER TABLE "user"
  ADD COLUMN "tinyCloudManageKeyEnabled" BOOLEAN NOT NULL DEFAULT true;
