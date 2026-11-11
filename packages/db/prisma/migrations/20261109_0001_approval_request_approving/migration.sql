-- Set when an approval is admitted, before signing starts. A lease: it stops counting after 30 seconds.
ALTER TABLE "approval_request" ADD COLUMN "approvingAt" TIMESTAMP(3);
