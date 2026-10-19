import { logMetric } from '../log';

// TC-1483: one row per (userId, app origin, UTC day), for scoreboard counts.
// Stores nothing else: no IP, user agent, DID, address or message content.

export const APP_SIGN_IN_RETENTION_DAYS = 35;
export const UNKNOWN_APP_ORIGIN = 'unknown';
const MAX_ORIGIN_LENGTH = 255;
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;

export type AppSignInDatabase = {
  appSignInDay: {
    upsert(args: {
      where: { userId_origin_day: { userId: string; origin: string; day: Date } };
      create: { userId: string; origin: string; day: Date };
      update: Record<string, never>;
    }): Promise<unknown>;
    deleteMany(args: { where: { day: { lt: Date } } }): Promise<unknown>;
  };
};

/** `scheme://host[:port]` for an http(s) URL; null for anything else. */
export function normalizeAppOrigin(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password) return null;
  const origin = url.origin;
  if (origin === 'null' || origin.length > MAX_ORIGIN_LENGTH) return null;
  return origin;
}

export function utcDay(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}

export function retentionCutoff(now: Date): Date {
  const cutoff = utcDay(now);
  cutoff.setUTCDate(cutoff.getUTCDate() - APP_SIGN_IN_RETENTION_DAYS);
  return cutoff;
}

/** Deletes rows older than the 35-day retention window. */
export async function pruneAppSignIns(database: AppSignInDatabase, now = new Date()): Promise<void> {
  await database.appSignInDay.deleteMany({ where: { day: { lt: retentionCutoff(now) } } });
}

let lastPruneAt = 0;

const FAILURE_LOG_INTERVAL_MS = 60_000;
let failuresSinceLog = 0;
let lastFailureLogAt = 0;

function noteRecordFailure(error: unknown): void {
  // A concurrent first sign-in of the day hits the PK: expected, not a failure.
  if ((error as { code?: unknown } | null)?.code === 'P2002') return;
  failuresSinceLog += 1;
  const now = Date.now();
  if (now - lastFailureLogAt < FAILURE_LOG_INTERVAL_MS) return;
  lastFailureLogAt = now;
  const count = failuresSinceLog;
  failuresSinceLog = 0;
  logMetric('warn', 'app_sign_in_record_failed', { count });
}

/** Test hook: forget the prune and failure-log clocks. */
export function resetAppSignInStateForTests(): void {
  lastPruneAt = 0;
  failuresSinceLog = 0;
  lastFailureLogAt = 0;
}

/**
 * Upsert on (userId, origin, day), so repeat sign-ins the same day add no
 * rows. Expired rows are pruned at most once an hour per process. Rejects on
 * DB errors: sign-in paths use `recordAppSignIn`.
 */
export async function writeAppSignIn(
  database: AppSignInDatabase,
  userId: string,
  appOrigin: unknown,
  now = new Date(),
): Promise<void> {
  const origin = normalizeAppOrigin(appOrigin) ?? UNKNOWN_APP_ORIGIN;
  await database.appSignInDay.upsert({
    where: { userId_origin_day: { userId, origin, day: utcDay(now) } },
    create: { userId, origin, day: utcDay(now) },
    update: {},
  });
  if (now.getTime() - lastPruneAt >= PRUNE_INTERVAL_MS) {
    lastPruneAt = now.getTime();
    await pruneAppSignIns(database, now);
  }
}

/**
 * Fire-and-forget sign-in record: returns immediately and never rejects, so a
 * metrics write cannot delay or fail a sign-in. Do not await. Failures are
 * counted and logged at most once a minute (count only, no ids).
 */
export function recordAppSignIn(
  database: AppSignInDatabase,
  userId: string,
  appOrigin: unknown,
  now = new Date(),
): void {
  void writeAppSignIn(database, userId, appOrigin, now).catch(noteRecordFailure);
}
