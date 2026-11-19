-- TC-3232: one row per account per Terms version accepted on the required Terms screen.
CREATE TABLE "terms_acceptance" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "documentId" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "textSha256" TEXT NOT NULL,
    "acceptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "surface" TEXT NOT NULL,
    "appVersion" TEXT NOT NULL,

    CONSTRAINT "terms_acceptance_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "terms_acceptance_userId_version_key" ON "terms_acceptance"("userId", "version");

ALTER TABLE "terms_acceptance" ADD CONSTRAINT "terms_acceptance_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Append-only: an acceptance is never rewritten. Rows go only with the account (the cascade above).
CREATE FUNCTION refuse_terms_acceptance_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'terms acceptance is append-only';
END $$;
CREATE TRIGGER terms_acceptance_append_only BEFORE UPDATE ON "terms_acceptance"
  FOR EACH ROW EXECUTE FUNCTION refuse_terms_acceptance_update();
