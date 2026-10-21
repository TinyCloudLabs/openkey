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
const SWEEP_MAX_AGE_MS = 7 * 24 * 3_600_000;

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
      continue;
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

  if (summary.candidates > 0) {
    withScheduledLogContext(() =>
      logTinyCloudBootstrapSweep('tinycloud_bootstrap_sweep_tick', {
        candidates: summary.candidates,
        claimed: summary.claimed,
        healed: summary.healed,
        stillFailed: summary.still_failed,
        skipped: summary.skipped,
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
