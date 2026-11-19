-- TC-1231: Apple server-to-server notifications (plan TC-1188 §6).
-- Apple Account rows keep their identity link when Apple reports a revocation;
-- these columns order late events and record the relay-email state.
ALTER TABLE "account" ADD COLUMN "appleRestoredAt" TIMESTAMP(3),
                      ADD COLUMN "appleEmailEventAt" TIMESTAMP(3),
                      ADD COLUMN "appleEmailUndeliverable" BOOLEAN NOT NULL DEFAULT false,
                      ADD COLUMN "revokedAt" TIMESTAMP(3);

-- Durable notification idempotency: one row per Apple JWS `jti`, kept indefinitely.
CREATE TABLE "apple_notification" (
    "jti" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "eventTime" TIMESTAMP(3) NOT NULL,
    "outcome" TEXT NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "apple_notification_pkey" PRIMARY KEY ("jti")
);
