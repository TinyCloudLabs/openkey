-- Split migration that applies the management credential default after the
-- enum value exists in a previous committed migration.

ALTER TABLE "organization_server_credential"
ALTER COLUMN "kind" SET DEFAULT 'MANAGEMENT';
