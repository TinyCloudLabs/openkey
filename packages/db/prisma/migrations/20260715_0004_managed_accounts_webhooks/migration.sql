CREATE TYPE "WebhookDeliveryStatus" AS ENUM ('PENDING', 'DELIVERED', 'FAILED');

CREATE TABLE "webhook_endpoint" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "url" TEXT NOT NULL,
  "eventTypes" TEXT[],
  "secretHash" TEXT NOT NULL,
  "sealedSecret" TEXT NOT NULL,
  "active" BOOLEAN NOT NULL DEFAULT true,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "webhook_endpoint_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "webhook_endpoint_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "webhook_endpoint_org_active_idx" ON "webhook_endpoint"("organizationId", "active");

CREATE TABLE "webhook_delivery" (
  "id" TEXT NOT NULL,
  "endpointId" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "managedAccountId" TEXT NOT NULL,
  "eventType" TEXT NOT NULL,
  "custodyEpoch" INTEGER NOT NULL,
  "payload" JSONB NOT NULL,
  "status" "WebhookDeliveryStatus" NOT NULL DEFAULT 'PENDING',
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "lastAttemptAt" TIMESTAMP(3),
  "deliveredAt" TIMESTAMP(3),
  "responseDigest" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "webhook_delivery_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "webhook_delivery_endpoint_fkey" FOREIGN KEY ("endpointId") REFERENCES "webhook_endpoint"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "webhook_delivery_org_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "webhook_delivery_account_fkey" FOREIGN KEY ("managedAccountId") REFERENCES "managed_account"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "webhook_delivery_ordering_key" ON "webhook_delivery"("endpointId", "managedAccountId", "eventType", "custodyEpoch");
CREATE INDEX "webhook_delivery_status_created_idx" ON "webhook_delivery"("status", "createdAt");

CREATE OR REPLACE FUNCTION openkey_webhook_tenant_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM "webhook_endpoint" endpoint WHERE endpoint."id" = NEW."endpointId" AND endpoint."organizationId" = NEW."organizationId")
     OR NOT EXISTS (SELECT 1 FROM "managed_account" account WHERE account."id" = NEW."managedAccountId" AND account."organizationId" = NEW."organizationId") THEN
    RAISE EXCEPTION 'webhook delivery crosses organization boundary';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER webhook_delivery_tenant_guard BEFORE INSERT OR UPDATE ON "webhook_delivery"
  FOR EACH ROW EXECUTE FUNCTION openkey_webhook_tenant_guard();
