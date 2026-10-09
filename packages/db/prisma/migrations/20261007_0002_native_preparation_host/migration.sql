ALTER TABLE "tinycloud_native_preparation" ADD COLUMN "tinycloudHost" TEXT NOT NULL DEFAULT '';
ALTER TABLE "tinycloud_native_preparation" ALTER COLUMN "tinycloudHost" DROP DEFAULT;
