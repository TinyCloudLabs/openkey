import { getPrisma, type PrismaClient } from '@openkey/db';
import { unsealManagedKey } from './managed-key-signing';
import {
  ensureTinyCloudBootstrap,
  TINYCLOUD_BOOTSTRAP_VERSION,
  trustedTinyCloudBootstrapHost,
  type TinyCloudBootstrapOutcome,
} from './tinycloud-bootstrap';
import { SWEEP_RETRYABLE_CODES } from './tinycloud-bootstrap-budget';
import { logError, logTinyCloudBootstrapSweep, withScheduledLogContext } from '../log';

const SWEEP_TICK_MS = 60_000;
/** Wait after the failure (or stale lock) before sweep attempt N+1. The length is also the attempt cap. */
const SWEEP_DELAYS_MS: readonly number[] = [5 * 60_000, 30 * 60_000, 2 * 3_600_000, 6 * 3_600_000];
const SWEEP_BATCH = 10;
const SWEEP_MAX_AGE_MS = 30 * 24 * 3_600_000;
/** Written to a reaped row that had no code. Not in SWEEP_RETRYABLE_CODES: the sweep never re-runs it. */
const LEASE_EXPIRED_CODE = 'tinycloud_bootstrap_lease_expired';

interface SweepKey {
  id: string;
  userId: string | null;
  address: string;
  keyType: string;
  sealedBlob: string | null;
  sealingContext: string | null;
}

export interface TinyCloudBootstrapSweepSummary {
  candidates: number;
  claimed: number;
  healed: number;
  still_failed: number;
  skipped: number;
  /** Abandoned leases marked failed this tick. Absent when the tick did not run (kill switch). */
  reaped?: number;
}

export interface SweepOptions {
  prisma?: PrismaClient;
  now?: Date;
  delaysMs?: readonly number[];
  batch?: number;
  resolveKey?: (key: SweepKey) => Promise<string>;
}

const defaultResolveKey = async (key: SweepKey): Promise<string> => {
  if (!key.sealedBlob) throw new Error('TinyCloud bootstrap sweep: managed key has no sealed key data');
  return unsealManagedKey(key, key.sealedBlob);
};

/**
 * Marks abandoned setup leases failed. A row left `in_progress` whose lease has expired (or was
 * never set) and whose code the sweep does not retry is written `failed`, with
 * `tinycloud_bootstrap_lease_expired` when it had no code. This never unseals a key and never
 * starts a run: the row keeps its `attemptId`, so only a fresh approval (or, for a retryable
 * code, the existing sweep route below) can run it again. Each write is a compare-and-set on the
 * state read, so an approval that claims the row first is never overwritten.
 */
async function reapAbandonedLeases(prisma: PrismaClient, now: Date, batch: number): Promise<number> {
  const rows = await prisma.tinyCloudBootstrapState.findMany({
    where: {
      bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION,
      tinycloudHost: trustedTinyCloudBootstrapHost(),
      chainId: 1,
      checkedAt: { gte: new Date(now.getTime() - SWEEP_MAX_AGE_MS) },
      status: 'in_progress',
      AND: [
        { OR: [{ lockExpiresAt: { lt: now } }, { lockExpiresAt: null }] },
        // `notIn` never matches NULL, so a row with no code needs its own branch.
        { OR: [{ failureCode: null }, { failureCode: { notIn: [...SWEEP_RETRYABLE_CODES] } }] },
      ],
    },
    select: { id: true, attemptId: true, lockExpiresAt: true, checkedAt: true, failureCode: true },
    orderBy: { checkedAt: 'asc' },
    take: batch,
  });

  let reaped = 0;
  for (const row of rows) {
    if (process.env.TINYCLOUD_BOOTSTRAP_SWEEP === 'off') break;
    const failureCode = row.failureCode ?? LEASE_EXPIRED_CODE;
    const written = await prisma.tinyCloudBootstrapState.updateMany({
      where: {
        id: row.id,
        status: 'in_progress',
        attemptId: row.attemptId,
        lockExpiresAt: row.lockExpiresAt,
        checkedAt: row.checkedAt,
        failureCode: row.failureCode,
      },
      data: {
        status: 'failed',
        failureCode,
        failureReason: 'TinyCloud account setup was abandoned before it finished: its lease expired.',
        lockExpiresAt: null,
      },
    });
    if (written.count !== 1) continue;
    reaped++;
    withScheduledLogContext(() => logTinyCloudBootstrapSweep('tinycloud_bootstrap_sweep_reaped', { errorCode: failureCode }));
  }
  return reaped;
}

/**
 * Retries failed TinyCloud account setup in the background. Each candidate is claimed with a
 * compare-and-set on the state the sweep observed, so approvals, other ticks and other API
 * instances cannot sign the same row concurrently. Attempts are counted on the row, so a restart
 * resumes from the stored count instead of starting over.
 */
export async function sweepTinyCloudBootstrapOnce(opts: SweepOptions = {}): Promise<TinyCloudBootstrapSweepSummary> {
  const summary: TinyCloudBootstrapSweepSummary = { candidates: 0, claimed: 0, healed: 0, still_failed: 0, skipped: 0 };
  // Read per tick so the switch takes effect without a restart.
  if (process.env.TINYCLOUD_BOOTSTRAP_SWEEP === 'off') return summary;

  const prisma = opts.prisma ?? getPrisma();
  const now = opts.now ?? new Date();
  const delays = opts.delaysMs ?? SWEEP_DELAYS_MS;
  const resolveKey = opts.resolveKey ?? defaultResolveKey;
  const rows = await prisma.tinyCloudBootstrapState.findMany({
    where: {
      bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION,
      tinycloudHost: trustedTinyCloudBootstrapHost(),
      chainId: 1,
      failureCode: { in: [...SWEEP_RETRYABLE_CODES] },
      sweepAttempts: { lt: delays.length },
      checkedAt: { gte: new Date(now.getTime() - SWEEP_MAX_AGE_MS) },
      AND: [
        { OR: [{ status: 'failed' }, { status: 'in_progress', lockExpiresAt: { lt: now } }] },
        { OR: delays.map((delay, attempt) => ({ sweepAttempts: attempt, checkedAt: { lte: new Date(now.getTime() - delay) } })) },
      ],
      user: { is: { autoSignEnabled: true } },
      key: { is: { keyType: 'MANAGED', archivedAt: null, sealedBlob: { not: null } } },
    },
    select: {
      id: true,
      userId: true,
      keyId: true,
      chainId: true,
      tinycloudHost: true,
      status: true,
      attemptId: true,
      sweepAttempts: true,
      checkedAt: true,
      key: {
        select: { id: true, userId: true, address: true, keyType: true, sealedBlob: true, sealingContext: true },
      },
    },
    orderBy: { checkedAt: 'asc' },
    take: opts.batch ?? SWEEP_BATCH,
  });
  summary.candidates = rows.length;

  for (const row of rows) {
    // Read per row, like per tick: a switch flipped during a long tick stops it at the next row.
    if (process.env.TINYCLOUD_BOOTSTRAP_SWEEP === 'off') break;
    const status = row.status;
    if (status !== 'failed' && status !== 'in_progress') {
      summary.skipped++;
      continue;
    }
    const sweepAttempt = row.sweepAttempts + 1;
    const startedAt = Date.now();
    const claim = { won: false };
    let outcome: TinyCloudBootstrapOutcome;
    try {
      outcome = await ensureTinyCloudBootstrap({
        prisma,
        userId: row.userId,
        key: { id: row.key.id, address: row.key.address, keyType: row.key.keyType },
        privateKey: () => resolveKey(row.key),
        host: row.tinycloudHost,
        chainId: row.chainId,
        sweepClaim: {
          observed: { status, sweepAttempts: row.sweepAttempts, checkedAt: row.checkedAt, attemptId: row.attemptId },
          onClaimed: () => {
            claim.won = true;
            summary.claimed++;
          },
        },
      });
    } catch (error) {
      withScheduledLogContext(() => logError('error', 'tinycloud_bootstrap_sweep_failed', error));
      // A throw before the claim was won touched nothing. After it, the attempt was spent: count it
      // and log it below, so the last attempt still ends in `exhausted`.
      if (!claim.won) continue;
      outcome = {
        status: 'failed',
        errorCode: 'tinycloud_bootstrap_failed',
        errorMessage: error instanceof Error ? error.message : String(error),
      };
    } finally {
      // The sealed key is only needed for the run; do not keep it in memory after the row is handled.
      row.key.sealedBlob = null;
    }

    if (!claim.won) {
      summary.skipped++;
      continue;
    }
    const durationMs = Date.now() - startedAt;
    if (outcome.status === 'complete') {
      summary.healed++;
      withScheduledLogContext(() => logTinyCloudBootstrapSweep('tinycloud_bootstrap_sweep_healed', { sweepAttempt, durationMs }));
    } else {
      summary.still_failed++;
      const errorCode = outcome.status === 'failed' ? outcome.errorCode : undefined;
      withScheduledLogContext(() =>
        logTinyCloudBootstrapSweep(
          sweepAttempt >= delays.length ? 'tinycloud_bootstrap_sweep_exhausted' : 'tinycloud_bootstrap_sweep_still_failed',
          { sweepAttempt, errorCode, durationMs },
        ),
      );
    }
  }

  // After the re-run loop: reaping never signs, so it does not compete with the loop for time or for rows.
  if (process.env.TINYCLOUD_BOOTSTRAP_SWEEP !== 'off') {
    summary.reaped = await reapAbandonedLeases(prisma, now, opts.batch ?? SWEEP_BATCH);
  }

  if (summary.candidates > 0 || summary.reaped) {
    withScheduledLogContext(() =>
      logTinyCloudBootstrapSweep('tinycloud_bootstrap_sweep_tick', {
        candidates: summary.candidates,
        claimed: summary.claimed,
        healed: summary.healed,
        stillFailed: summary.still_failed,
        skipped: summary.skipped,
        reaped: summary.reaped || undefined,
      }),
    );
  }
  return summary;
}

let sweepTimer: ReturnType<typeof setInterval> | undefined;

/** Starts the in-process sweep timer. Idempotent: a second call returns the same timer's stop function. */
export function startTinyCloudBootstrapSweep(opts: SweepOptions = {}): () => void {
  if (!sweepTimer) {
    let running = false;
    sweepTimer = setInterval(() => {
      if (running) return;
      running = true;
      void sweepTinyCloudBootstrapOnce(opts)
        .catch((error) => withScheduledLogContext(() => logError('error', 'tinycloud_bootstrap_sweep_failed', error)))
        .finally(() => { running = false; });
    }, SWEEP_TICK_MS);
    sweepTimer.unref();
  }
  return () => {
    if (sweepTimer) clearInterval(sweepTimer);
    sweepTimer = undefined;
  };
}
