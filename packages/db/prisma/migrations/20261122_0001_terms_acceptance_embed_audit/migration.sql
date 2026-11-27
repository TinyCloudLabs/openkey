-- An acceptance agreed in the embedded OpenKey frame (Bearer session) records how a person was shown to be
-- present. Additive and nullable: earlier rows and the previous API image are unaffected, and nothing is
-- backfilled (the append-only trigger refuses updates).
ALTER TABLE "terms_acceptance"
  ADD COLUMN "sessionId" TEXT,
  ADD COLUMN "proof" TEXT,
  ADD COLUMN "proofAt" TIMESTAMP(3),
  ADD COLUMN "requestOrigin" TEXT,
  ADD COLUMN "embedOriginClaimed" TEXT;
