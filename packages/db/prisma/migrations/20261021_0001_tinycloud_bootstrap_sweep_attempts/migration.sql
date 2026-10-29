-- TC-1711: count background sweep attempts per bootstrap state row. Additive; existing rows default to 0.
ALTER TABLE "tinycloud_bootstrap_state" ADD COLUMN "sweepAttempts" INTEGER NOT NULL DEFAULT 0;
