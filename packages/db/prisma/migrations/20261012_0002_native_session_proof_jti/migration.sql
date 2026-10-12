-- Persist proof identifiers through the end of their accepted iat window.
CREATE TABLE "native_session_proof_jti" (
  "jti_hash" TEXT NOT NULL,
  "grant_id" TEXT NOT NULL,
  "expires_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "native_session_proof_jti_pkey" PRIMARY KEY ("jti_hash")
);

CREATE INDEX "native_session_proof_jti_expires_at_idx"
  ON "native_session_proof_jti"("expires_at");
