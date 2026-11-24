// The fail-closed off switch for renewal leases (TC-3088).
//
// `OPENKEY_RENEWAL_LEASES=enabled` offers leases. Any other value only stops NEW leases: the node keeps renewing
// the ones it already holds, because OpenKey signed each lease once and is not in the renewal path. Setting the
// value to exactly `stop` also revokes every live lease, from inside the API (revoking needs OpenKey's sealed keys),
// and keeps retrying the ones the node did not confirm until none remain.
import type { PrismaClient } from '@openkey/db';
import { logError, logMetric, withScheduledLogContext } from '../log';
import { nativeStopsPendingWhere, revokeRenewalLeases, type LeaseRevocationDeps } from './renewal-lease-revocation';

export const SWEEP_INTERVAL_MS = 5 * 60_000;
/** Lets the database and the node connections settle after boot before the first pass. */
const FIRST_PASS_DELAY_MS = 30_000;

export type RenewalLeaseSweepDatabase = Pick<PrismaClient, 'renewalLease' | 'ethereumKey' | '$transaction'>;

export interface RenewalLeaseSweepReport {
  /** Accounts that held a live lease at the start of the pass. */
  users: number;
  stopped: number;
  /** Signed by an external wallet: only that wallet can revoke it, so it keeps renewing. */
  walletRequired: number;
  /** The node did not confirm the revocation (or the account was busy): retried on the next pass. */
  notStopped: number;
}

export function renewalLeaseStopSweepEnabled(): boolean {
  return process.env.OPENKEY_RENEWAL_LEASES === 'stop';
}

/** One pass: asks the node to revoke every live lease an OpenKey-held key signed. Safe to run twice. */
export async function stopAllRenewalLeasesOnce(
  db: RenewalLeaseSweepDatabase,
  deps?: LeaseRevocationDeps,
  now: () => Date = () => new Date(),
  nativeOnly = false,
): Promise<RenewalLeaseSweepReport> {
  const report: RenewalLeaseSweepReport = { users: 0, stopped: 0, walletRequired: 0, notStopped: 0 };
  // The same set the owner's list shows: not stopped, not refused by the node, not past its end.
  const holders = await db.renewalLease.findMany({
    where: nativeOnly ? { nativeRenewal: { is: nativeStopsPendingWhere(now()) } } : {
      OR: [{ revokedAt: null, neverAdmittedAt: null, leaseExpiresAt: { gt: now() } }, { nativeRenewal: { is: nativeStopsPendingWhere(now()) } }],
    },
    select: { userId: true },
    distinct: ['userId'],
  });
  report.users = holders.length;
  for (const { userId } of holders) {
    try {
      // Another stop already holds this account: its leases are counted on the next pass.
      const result = await revokeRenewalLeases(db, userId, nativeOnly ? { kind: 'native-stop' } : { kind: 'all', includeNativeStops: true }, deps, { waitForLock: false });
      report.stopped += result.stopped.length;
      for (const left of result.notStopped) {
        if (left.reason === 'wallet_required') report.walletRequired += 1;
        else report.notStopped += 1;
      }
    } catch {
      report.notStopped += 1;
    }
  }
  return report;
}

let timer: ReturnType<typeof setInterval> | undefined;
let first: ReturnType<typeof setTimeout> | undefined;

/**
 * Retries queued native stops. The global stop value also settles every live lease.
 * Idempotent: a second call returns the same stop function.
 */
export function startRenewalLeaseStopSweep(db: RenewalLeaseSweepDatabase, deps?: LeaseRevocationDeps): () => void {
  if (!timer) {
    let running = false;
    const pass = () => {
      if (running) return;
      running = true;
      const nativeOnly = !renewalLeaseStopSweepEnabled();
      void stopAllRenewalLeasesOnce(db, deps, undefined, nativeOnly)
        .then((report) => withScheduledLogContext(() => {
          if (nativeOnly && report.users === 0) return;
          logMetric('info', 'renewal_lease_sweep_stopped', { count: report.stopped });
          logMetric(report.walletRequired > 0 ? 'warn' : 'info', 'renewal_lease_sweep_wallet_required', { count: report.walletRequired });
          logMetric(report.notStopped > 0 ? 'warn' : 'info', 'renewal_lease_sweep_not_stopped', { count: report.notStopped });
        }))
        .catch((error) => withScheduledLogContext(() => logError('error', 'renewal_lease_sweep_failed', error)))
        .finally(() => { running = false; });
    };
    timer = setInterval(pass, SWEEP_INTERVAL_MS);
    timer.unref();
    first = setTimeout(pass, FIRST_PASS_DELAY_MS);
    first.unref();
  }
  return () => {
    clearInterval(timer);
    clearTimeout(first);
    timer = undefined;
    first = undefined;
  };
}
