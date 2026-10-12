import type { TinyCloudBootstrapOutcome } from './tinycloud-bootstrap';

export const DEFAULT_TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS = 2500;

/** Read per call so tests and tuning see the current env. Invalid or negative → default. */
export function tinyCloudBootstrapSyncBudgetMs(
  env: Record<string, string | undefined> = process.env,
): number {
  const configured = env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
  const budget = configured?.trim() ? Number(configured) : NaN;
  return Number.isFinite(budget) && budget >= 0
    ? budget
    : DEFAULT_TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
}

export type BudgetedTinyCloudBootstrapOutcome = TinyCloudBootstrapOutcome | { status: 'pending' };

type BackgroundObserver = (outcome: TinyCloudBootstrapOutcome) => void;
let backgroundObserver: BackgroundObserver | undefined;

/** Test seam, same idiom as setTinyCloudBootstrapExecutorForTests. */
export function setTinyCloudBootstrapBackgroundObserverForTests(observer?: BackgroundObserver): void {
  backgroundObserver = observer;
}

/**
 * Wait up to the sync budget, then let bootstrap finish under its existing lock/heartbeat.
 * Executor/probe failures are recorded by ensureTinyCloudBootstrap in its state row.
 * Rejections outside that lock's try cannot be recorded without an attemptId: log them
 * here, and let the two-minute lock TTL free any abandoned in-progress row.
 * Never rejects; the original promise gets a rejection handler before the race starts.
 */
export async function awaitTinyCloudBootstrapWithinBudget(
  bootstrap: Promise<TinyCloudBootstrapOutcome>,
  options: { logPrefix: string; logContext: { keyId: string; [k: string]: unknown }; budgetMs?: number },
): Promise<BudgetedTinyCloudBootstrapOutcome> {
  const settled = bootstrap.then(
    (outcome) => outcome,
    (error): TinyCloudBootstrapOutcome => ({
      status: 'failed',
      errorCode: 'tinycloud_bootstrap_crashed',
      errorMessage: error instanceof Error ? error.message : String(error),
    }),
  );
  let timer: ReturnType<typeof setTimeout> | undefined;
  let result: BudgetedTinyCloudBootstrapOutcome;
  try {
    result = await Promise.race([
      settled,
      new Promise<{ status: 'pending' }>((resolve) => {
        timer = setTimeout(() => resolve({ status: 'pending' }), options.budgetMs ?? tinyCloudBootstrapSyncBudgetMs());
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }

  if (result.status === 'pending') {
    // Only identifiers belong in the background closure, never the bootstrap input/key.
    const { logPrefix, logContext } = options;
    void settled.then((outcome) => {
      if (outcome.status === 'failed') {
        const label = outcome.errorCode === 'tinycloud_bootstrap_crashed' ? 'crashed' : 'failed';
        console.error(`${logPrefix} TinyCloud bootstrap ${label} (async)`, {
          ...logContext,
          errorCode: outcome.errorCode,
          errorMessage: outcome.errorMessage,
        });
      } else {
        console.log(`${logPrefix} TinyCloud bootstrap finished (async)`, { ...logContext, status: outcome.status });
      }
      try {
        backgroundObserver?.(outcome);
      } catch {
        // A test observer must never turn settled background work into an unhandled rejection.
      }
    });
  }
  return result;
}
