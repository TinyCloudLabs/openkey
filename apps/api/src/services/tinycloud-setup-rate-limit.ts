// TC-3657: per-owner rate limit on the outside-app setup endpoint. The SDK-side 24h
// throttle in `localStorage` (js-sdk#1113 `handle-account-setup-required.ts`) is a UX
// hint the outside app owns; THIS limiter is the security guarantee.
//
// Persistence: the counter lives in Postgres via `TinyCloudSetupRateLimitBucket`. Atomic
// increment via UPSERT keyed by `${action}:${subject.toLowerCase()}:${windowStartMs}` so
// parallel API replicas share one counter per owner per action per hourly window. An
// in-memory implementation is retained for tests and local dev.
//
// Kept separate from `NativeUserAction`: that type is the native consent routes' contract
// and should not grow.

import type { PrismaClient } from '@openkey/db';

const WINDOW_MS = 60 * 60_000; // 1 hour window

/** Per-owner actions the setup endpoint tracks. */
export type TinyCloudSetupAction = 'mint' | 'publish';

const DEFAULT_LIMITS: Record<TinyCloudSetupAction, number> = {
  mint: 10,      // at most 10 widget renders per owner per hour
  publish: 5,    // at most 5 publish attempts per owner per hour
};

export type TinyCloudSetupLimiter = (subject: string, action: TinyCloudSetupAction, now?: number) => Promise<number>;

/** Prisma-backed limiter (default in production). `UPSERT ... DO UPDATE SET count = count + 1` is the atomic
 *  path; after the increment the function checks whether the new count is within the limit and returns the
 *  appropriate `retry-after` seconds. */
export function createPrismaTinyCloudSetupLimiter(
  prisma: PrismaClient,
  limits: Record<TinyCloudSetupAction, number> = DEFAULT_LIMITS,
): TinyCloudSetupLimiter {
  return async (subject, action, now = Date.now()) => {
    const windowStartMs = Math.floor(now / WINDOW_MS) * WINDOW_MS;
    const id = `${action}:${subject.toLowerCase()}:${windowStartMs}`;
    // UPSERT with atomic increment on conflict. We run it in two steps because Prisma's
    // `upsert` with an atomic `increment` isn't directly supported for partial updates;
    // a raw query is both clearer and portable across Prisma versions.
    const rows = await prisma.$queryRaw<{ count: number }[]>`
      INSERT INTO "tinycloud_setup_rate_limit_bucket" ("id", "action", "subject", "windowStartMs", "count", "updatedAt")
      VALUES (${id}, ${action}, ${subject.toLowerCase()}, ${BigInt(windowStartMs)}, 1, NOW())
      ON CONFLICT ("id") DO UPDATE SET "count" = "tinycloud_setup_rate_limit_bucket"."count" + 1, "updatedAt" = NOW()
      RETURNING "count";
    `;
    const count = rows[0]?.count ?? 0;
    if (count > limits[action]) {
      const resetAt = windowStartMs + WINDOW_MS;
      return Math.max(1, Math.ceil((resetAt - now) / 1_000));
    }
    return 0;
  };
}

/** In-memory limiter for tests + local dev. Mirrors the public shape. Not safe across
 *  replicas; production must use `createPrismaTinyCloudSetupLimiter`. */
export function createInMemoryTinyCloudSetupLimiter(
  limits: Record<TinyCloudSetupAction, number> = DEFAULT_LIMITS,
  maxBuckets = 10_000,
): TinyCloudSetupLimiter {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  return async (subject, action, now = Date.now()) => {
    const key = `${action}:${subject.toLowerCase()}`;
    const prior = buckets.get(key);
    const bucket = prior && prior.resetAt > now ? prior : { count: 0, resetAt: now + WINDOW_MS };
    if (bucket.count >= limits[action]) return Math.max(1, Math.ceil((bucket.resetAt - now) / 1_000));
    bucket.count++;
    buckets.delete(key);
    buckets.set(key, bucket);
    if (buckets.size > maxBuckets) buckets.delete(buckets.keys().next().value!);
    return 0;
  };
}
