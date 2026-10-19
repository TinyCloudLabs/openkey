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

/** Test hook: forget the last prune time. */
export function resetAppSignInPruneClock(): void {
  lastPruneAt = 0;
}

/**
 * Record a sign-in. Upsert on (userId, origin, day), so repeat sign-ins the
 * same day add no rows. Never throws: a metrics write must not fail a sign-in.
 * Expired rows are pruned at most once an hour per process.
 */
export async function recordAppSignIn(
  database: AppSignInDatabase,
  userId: string,
  appOrigin: unknown,
  now = new Date(),
): Promise<void> {
  const origin = normalizeAppOrigin(appOrigin) ?? UNKNOWN_APP_ORIGIN;
  try {
    await database.appSignInDay.upsert({
      where: { userId_origin_day: { userId, origin, day: utcDay(now) } },
      create: { userId, origin, day: utcDay(now) },
      update: {},
    });
    if (now.getTime() - lastPruneAt >= PRUNE_INTERVAL_MS) {
      lastPruneAt = now.getTime();
      await pruneAppSignIns(database, now);
    }
  } catch {
    // Concurrent first sign-in of the day (unique violation) or a DB outage.
  }
}
