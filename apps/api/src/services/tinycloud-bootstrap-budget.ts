import { logTinyCloudBootstrapBackground, type RequestedSpaceHosted } from '../log';
import type {
  TinyCloudBootstrapOutcome,
  TinyCloudBootstrapRequestedSpaceReport,
} from './tinycloud-bootstrap';

export const DEFAULT_TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS = 2500;
const MAX_TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS = 60_000;

/** Read per call. Invalid or negative → default; cap at 60 seconds to avoid timer overflow. */
export function tinyCloudBootstrapSyncBudgetMs(
  env: Record<string, string | undefined> = process.env,
): number {
  const configured = env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
  const budget = configured?.trim() ? Number(configured) : NaN;
  return Number.isFinite(budget) && budget >= 0
    ? Math.min(budget, MAX_TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS)
    : DEFAULT_TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
}

export const DEFAULT_TINYCLOUD_REQUESTED_SPACE_TIMEOUT_MS = 10_000;

/**
 * How long an approval waits for the node to host the space it asked for (TC-1608). Read per
 * call from TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS; invalid or negative → default; cap 60 s.
 */
export function tinyCloudRequestedSpaceTimeoutMs(
  env: Record<string, string | undefined> = process.env,
): number {
  const configured = env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS;
  const timeout = configured?.trim() ? Number(configured) : NaN;
  return Number.isFinite(timeout) && timeout >= 0
    ? Math.min(timeout, MAX_TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS)
    : DEFAULT_TINYCLOUD_REQUESTED_SPACE_TIMEOUT_MS;
}

/** Wait before each background retry of a failed run: three retries, 5 s, 15 s, 45 s. */
export const DEFAULT_TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS: readonly number[] = [5_000, 15_000, 45_000];
const MAX_TINYCLOUD_BOOTSTRAP_RETRY_DELAY_MS = 5 * 60_000;
const MAX_TINYCLOUD_BOOTSTRAP_RETRIES = 5;

/**
 * Read per call from TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS: comma-separated non-negative
 * milliseconds, one per retry (at most 5, each capped at 5 minutes), or `off`. Invalid → default.
 */
export function tinyCloudBootstrapRetryDelaysMs(
  env: Record<string, string | undefined> = process.env,
): readonly number[] {
  const configured = env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS?.trim();
  if (!configured) return DEFAULT_TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS;
  if (configured.toLowerCase() === 'off') return [];
  const delays = configured.split(',').map((part) => (part.trim() ? Number(part) : NaN));
  return delays.every((delay) => Number.isFinite(delay) && delay >= 0)
    ? delays.slice(0, MAX_TINYCLOUD_BOOTSTRAP_RETRIES).map((delay) => Math.min(delay, MAX_TINYCLOUD_BOOTSTRAP_RETRY_DELAY_MS))
    : DEFAULT_TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS;
}

export type BudgetedTinyCloudBootstrapOutcome = TinyCloudBootstrapOutcome | { status: 'pending' };

type BackgroundObserver = (outcome: TinyCloudBootstrapOutcome) => void;
let backgroundObserver: BackgroundObserver | undefined;

/** Test seam, same idiom as setTinyCloudBootstrapExecutorForTests. */
export function setTinyCloudBootstrapBackgroundObserverForTests(observer?: BackgroundObserver): void {
  backgroundObserver = observer;
}

/** Rejections outside the bootstrap lock's try cannot be recorded in the state row: normalize them. */
function settleBootstrap(bootstrap: () => Promise<TinyCloudBootstrapOutcome>): Promise<TinyCloudBootstrapOutcome> {
  return (async () => bootstrap())().then(
    (outcome) => outcome,
    (error): TinyCloudBootstrapOutcome => ({
      status: 'failed',
      errorCode: 'tinycloud_bootstrap_crashed',
      errorMessage: error instanceof Error ? error.message : String(error),
    }),
  );
}

function recordBackgroundOutcome(
  outcome: TinyCloudBootstrapOutcome,
  fields: { attempt: number; startedAt: number; requestedSpaceHosted?: RequestedSpaceHosted },
): void {
  logTinyCloudBootstrapBackground(
    outcome.status === 'failed' ? 'tinycloud_bootstrap_background_failed' : 'tinycloud_bootstrap_background_completed',
    {
      errorCode: outcome.status === 'failed' ? outcome.errorCode : undefined,
      durationMs: performance.now() - fields.startedAt,
      attempt: fields.attempt,
      requestedSpaceHosted: fields.requestedSpaceHosted,
    },
  );
  try {
    backgroundObserver?.(outcome);
  } catch {
    // A test observer must never turn settled background work into an unhandled rejection.
  }
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
  options: { budgetMs?: number } = {},
): Promise<BudgetedTinyCloudBootstrapOutcome> {
  const startedAt = performance.now();
  const settled = settleBootstrap(() => bootstrap);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let result: BudgetedTinyCloudBootstrapOutcome;
  try {
    result = await Promise.race([
      settled,
      new Promise<{ status: 'pending' }>((resolve) => {
        timer = setTimeout(
          () => resolve({ status: 'pending' }),
          Math.min(options.budgetMs ?? tinyCloudBootstrapSyncBudgetMs(), MAX_TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS),
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }

  if (result.status === 'pending') {
    void settled.then((outcome) => recordBackgroundOutcome(outcome, { attempt: 1, startedAt }));
  }
  return result;
}

/** What the approval learns about the space it asked for. Only `hosted` and `complete` mean ready. */
export type RequestedSpaceResult =
  /** The node confirmed the space is hosted, during this approval. */
  | { status: 'hosted' }
  /** Setup was already complete before this approval. */
  | { status: 'complete' }
  /** Another approval's run holds the lock and will host it. */
  | { status: 'pending' }
  /** Hosting did not finish within the timeout; the run continues in the background. */
  | { status: 'timeout' }
  | { status: 'skipped' }
  /** The first run failed and a background retry is scheduled; `failed` means no retry will follow. */
  | { status: 'retrying'; errorCode: string; errorMessage: string }
  | { status: 'failed'; errorCode: string; errorMessage: string };

export interface RequestedSpaceAttempt {
  /** 1 for the approval's own run, then one per background retry. */
  attempt: number;
  /** The node already confirmed the space in an earlier attempt of this approval. */
  alreadyHosted: boolean;
  report: (report: TinyCloudBootstrapRequestedSpaceReport) => void;
}

/** Contention for the lock is not a failure of this run: its holder logs and retries. */
const NON_RETRYABLE_ERROR_CODES: Record<string, true> = {
  tinycloud_bootstrap_expired_request: true,
  tinycloud_bootstrap_untrusted_host: true,
  tinycloud_bootstrap_in_progress: true,
};

/**
 * Failure codes the background sweep retries. Allowlist, not denylist: a code the sweep does not
 * know about (including null) is never retried without an explicit decision here.
 */
export const SWEEP_RETRYABLE_CODES: readonly string[] = [
  'tinycloud_bootstrap_node_timeout',
  'tinycloud_bootstrap_failed',
  'tinycloud_bootstrap_space_not_hosted',
];

function requestedSpaceFromOutcome(outcome: TinyCloudBootstrapOutcome): RequestedSpaceResult {
  if (outcome.status !== 'failed') return { status: outcome.status };
  return outcome.errorCode === 'tinycloud_bootstrap_in_progress'
    ? { status: 'pending' }
    : { status: 'failed', errorCode: outcome.errorCode, errorMessage: outcome.errorMessage };
}

/**
 * Run the approval's bootstrap and wait only for the space it asked for (TC-1608).
 *
 * `runAttempt` starts one run (it owns the lock, hosts the requested space first and calls
 * `report` once the node confirms it). The result is what the approval can tell its client:
 * hosted, failed, or still running after the timeout. The run is never awaited past that.
 * Every outcome is logged with its duration, attempt and whether the space was hosted before
 * the response; a failed run is retried in the background after each delay, so recovery does not
 * wait for another approval. A failed state keeps its failure reason between attempts.
 * Never rejects.
 */
export async function hostRequestedSpaceWithinBudget(
  runAttempt: (attempt: RequestedSpaceAttempt) => Promise<TinyCloudBootstrapOutcome>,
  options: { timeoutMs?: number; retryDelaysMs?: readonly number[] } = {},
): Promise<RequestedSpaceResult> {
  let hosted = false;
  let resolveFirst!: (result: RequestedSpaceResult) => void;
  const first = new Promise<RequestedSpaceResult>((resolve) => { resolveFirst = resolve; });
  const start = (attempt: number) => settleBootstrap(() => runAttempt({
    attempt,
    alreadyHosted: hosted,
    report: (report) => {
      if (report.status === 'hosted') hosted = true;
      resolveFirst(report); // first report wins; later attempts' reports change nothing
    },
  }));

  const startedAt = performance.now();
  const firstRun = start(1);
  void firstRun.then((outcome) => resolveFirst(requestedSpaceFromOutcome(outcome)));

  let timer: ReturnType<typeof setTimeout> | undefined;
  let result: RequestedSpaceResult;
  try {
    result = await Promise.race([
      first,
      new Promise<RequestedSpaceResult>((resolve) => {
        timer = setTimeout(
          () => resolve({ status: 'timeout' }),
          Math.min(options.timeoutMs ?? tinyCloudRequestedSpaceTimeoutMs(), MAX_TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS),
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }

  const delays = options.retryDelaysMs ?? tinyCloudBootstrapRetryDelaysMs();
  // A failure a retry is about to try again is not final: the client keeps waiting, with the reason.
  if (result.status === 'failed' && delays.length > 0 && !NON_RETRYABLE_ERROR_CODES[result.errorCode]) {
    result = { ...result, status: 'retrying' };
  }
  const requestedSpaceHosted: RequestedSpaceHosted =
    result.status === 'hosted' ? 'yes' : result.status === 'timeout' ? 'timeout' : 'no';
  void (async () => {
    let outcome = await firstRun;
    let attemptStartedAt = startedAt;
    for (let attempt = 1; ; attempt += 1) {
      if (!(outcome.status === 'failed' && outcome.errorCode === 'tinycloud_bootstrap_in_progress')) {
        recordBackgroundOutcome(outcome, { attempt, startedAt: attemptStartedAt, requestedSpaceHosted });
      }
      const delay = delays[attempt - 1];
      if (outcome.status !== 'failed' || NON_RETRYABLE_ERROR_CODES[outcome.errorCode] || delay === undefined) return;
      await new Promise<void>((resolve) => {
        const retryTimer = setTimeout(resolve, delay);
        retryTimer.unref?.();
      });
      attemptStartedAt = performance.now();
      outcome = await start(attempt + 1);
    }
  })();
  return result;
}
