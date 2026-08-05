-- TC-484: users can immediately disable TinyCloud signing for one OAuth app
-- without removing the broader OpenKey login consent.
CREATE TABLE "tinycloud_manage_key_app_preference" (
  "userId" TEXT NOT NULL,
  "clientId" TEXT NOT NULL,
  "enabled" BOOLEAN NOT NULL DEFAULT true,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "tinycloud_manage_key_app_preference_pkey" PRIMARY KEY ("userId", "clientId"),
  CONSTRAINT "tinycloud_manage_key_app_preference_userId_fkey"
    FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "tinycloud_manage_key_app_preference_clientId_fkey"
    FOREIGN KEY ("clientId") REFERENCES "oauth_client"("clientId") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "tinycloud_manage_key_app_preference_clientId_idx"
  ON "tinycloud_manage_key_app_preference"("clientId");
