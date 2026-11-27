// Retention for the account-deletion event feed: rows older than ACCOUNT_DELETION_EVENT_RETENTION_DAYS are deleted
// (they hold addresses). Same timer pattern as the renewal lease sweep; an error is logged by class and never stops
// the server.
import type { PrismaClient } from '@openkey/db';
import { logError, logMetric, withScheduledLogContext } from '../log';
import {
  ACCOUNT_DELETION_EVENT_RETENTION_MS,
  ACCOUNT_DELETION_EVENT_SWEEP_FIRST_PASS_DELAY_MS,
  ACCOUNT_DELETION_EVENT_SWEEP_INTERVAL_MS,
} from './account-deletion-event';

export type AccountDeletionEventSweepDatabase = Pick<PrismaClient, 'accountDeletionEvent'>;

/** One pass: deletes every event whose `deletedAt` is older than the retention window. Returns the count deleted. */
export async function sweepAccountDeletionEventsOnce(
  db: AccountDeletionEventSweepDatabase,
  now: () => Date = () => new Date(),
): Promise<number> {
  const { count } = await db.accountDeletionEvent.deleteMany({
    where: { deletedAt: { lt: new Date(now().getTime() - ACCOUNT_DELETION_EVENT_RETENTION_MS) } },
  });
  return count;
}

let timer: ReturnType<typeof setInterval> | undefined;
let first: ReturnType<typeof setTimeout> | undefined;

/** Idempotent: a second call returns the same stop function. */
export function startAccountDeletionEventSweep(db: AccountDeletionEventSweepDatabase): () => void {
  if (!timer) {
    let running = false;
    const pass = () => {
      if (running) return;
      running = true;
      void sweepAccountDeletionEventsOnce(db)
        .then((count) => withScheduledLogContext(() => logMetric('info', 'account_deletion_event_sweep', { count })))
        .catch((error) => withScheduledLogContext(() => logError('error', 'account_deletion_event_sweep_failed', error)))
        .finally(() => { running = false; });
    };
    timer = setInterval(pass, ACCOUNT_DELETION_EVENT_SWEEP_INTERVAL_MS);
    timer.unref();
    first = setTimeout(pass, ACCOUNT_DELETION_EVENT_SWEEP_FIRST_PASS_DELAY_MS);
    first.unref();
  }
  return () => {
    clearInterval(timer);
    clearTimeout(first);
    timer = undefined;
    first = undefined;
  };
}
