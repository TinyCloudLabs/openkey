-- TC-2946: a renewal lease is recorded before its node admission, so a lease whose admission outcome is unknown
-- can still be found and settled. Leases are off until TC-2946 ships, so the table has no rows yet; a row would
-- make the NOT NULL column fail loudly.
-- "grantSiwe": the approved grant's SIWE message text (no signature), for the permissions Settings shows.
-- "admittedAt": set once the approval that admitted the lease is saved.
-- "neverAdmittedAt": set when the node refused to admit the lease and has no lease to revoke.
-- "leaseAuthorization": the signed lease, encrypted, kept only while admission is unconfirmed.
ALTER TABLE "renewal_lease" ADD COLUMN "grantSiwe" TEXT NOT NULL;
ALTER TABLE "renewal_lease" ADD COLUMN "admittedAt" TIMESTAMP(3);
ALTER TABLE "renewal_lease" ADD COLUMN "neverAdmittedAt" TIMESTAMP(3);
ALTER TABLE "renewal_lease" ADD COLUMN "leaseAuthorization" TEXT;
