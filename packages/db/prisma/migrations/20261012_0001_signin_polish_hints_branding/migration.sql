ALTER TABLE "tinycloud_native_request"
  ADD COLUMN "loginHint" TEXT,
  ADD COLUMN "loginMethod" TEXT;

ALTER TABLE "oauth_client"
  ADD COLUMN "themeBackgroundColor" TEXT,
  ADD COLUMN "themeAccentColor" TEXT;
