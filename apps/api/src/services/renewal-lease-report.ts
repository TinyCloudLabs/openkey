// A read-only count of the renewal leases that are still live (TC-3088), for the operator who decides whether to
// turn renewal off with `OPENKEY_RENEWAL_LEASES=stop`. Counts only: no lease id, user, address or node host.
// It imports nothing that needs the TEE, so it runs from an operator machine with a read-only DATABASE_URL.
import type { PrismaClient } from '@openkey/db';

export interface RenewalLeaseReport {
  /** Not stopped, not refused by the node, not past their end: what the node keeps renewing. */
  live: number;
  /** Signed by an OpenKey-held key: the stop sweep can revoke these. */
  openkeySigned: number;
  /** Signed by an external wallet (or by a key OpenKey no longer holds): only that wallet can revoke them. */
  walletSigned: number;
  /** Recorded before the node's admission was confirmed. */
  unconfirmed: number;
  accounts: number;
  earliestEnd: string | null;
  latestEnd: string | null;
}

export type RenewalLeaseReportDatabase = Pick<PrismaClient, '$queryRaw'>;

interface Row {
  live: number;
  openkey_signed: number;
  wallet_signed: number;
  unconfirmed: number;
  accounts: number;
  earliest_end: Date | null;
  latest_end: Date | null;
}

export async function renewalLeaseReport(db: RenewalLeaseReportDatabase, now: Date = new Date()): Promise<RenewalLeaseReport> {
  // The same "still live" set the stop sweep and the owner's Settings list use, and the same managed-key test the
  // revocation uses: a MANAGED key of that account with a sealed blob signs for that owner address.
  const rows = await db.$queryRaw<Row[]>`
    SELECT
      count(*)::int AS live,
      count(*) FILTER (WHERE k."id" IS NOT NULL)::int AS openkey_signed,
      count(*) FILTER (WHERE k."id" IS NULL)::int AS wallet_signed,
      count(*) FILTER (WHERE l."admittedAt" IS NULL)::int AS unconfirmed,
      count(DISTINCT l."userId")::int AS accounts,
      min(l."leaseExpiresAt") AS earliest_end,
      max(l."leaseExpiresAt") AS latest_end
    FROM "renewal_lease" l
    LEFT JOIN "ethereum_keys" k
      ON k."userId" = l."userId"
     AND lower(k."address") = lower(split_part(l."ownerDid", ':', 5))
     AND k."keyType" = 'MANAGED'
     AND k."sealedBlob" IS NOT NULL
    WHERE l."revokedAt" IS NULL AND l."neverAdmittedAt" IS NULL AND l."leaseExpiresAt" > ${now}`;
  const row = rows[0];
  return {
    live: row?.live ?? 0,
    openkeySigned: row?.openkey_signed ?? 0,
    walletSigned: row?.wallet_signed ?? 0,
    unconfirmed: row?.unconfirmed ?? 0,
    accounts: row?.accounts ?? 0,
    earliestEnd: row?.earliest_end ? new Date(row.earliest_end).toISOString() : null,
    latestEnd: row?.latest_end ? new Date(row.latest_end).toISOString() : null,
  };
}
