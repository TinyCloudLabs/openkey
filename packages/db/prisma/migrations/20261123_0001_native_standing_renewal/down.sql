DROP TRIGGER native_request_delete_queue_lease_stop ON "tinycloud_native_request";
DROP TRIGGER native_request_queue_lease_stop ON "tinycloud_native_request";
DROP TRIGGER native_grant_delete_queue_lease_stop ON "tinycloud_native_grant";
DROP TRIGGER native_grant_queue_lease_stop ON "tinycloud_native_grant";
DROP FUNCTION queue_native_lease_stop();

DROP TABLE "native_renewal_lease";
ALTER TABLE "tinycloud_native_grant" DROP COLUMN "renewalLeaseCid";
ALTER TABLE "tinycloud_native_preparation" DROP COLUMN "renewalChoice";
ALTER TABLE "tinycloud_native_request" DROP COLUMN "renewalAsk", DROP COLUMN "renewalLeaseCid";
