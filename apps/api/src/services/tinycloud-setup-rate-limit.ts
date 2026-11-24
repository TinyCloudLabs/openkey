// TC-3657 / TC-3893: per-owner rate limiters backed by `TinyCloudSetupRateLimitBucket`
// (Prisma UPSERT, replica-safe) with an in-memory implementation for unit tests.
//
// Bucket keys are `${action}:${subject.toLowerCase()}:${windowStartMs}` so distinct
// features (`mint`/`publish` for setup; `registry_change_prepare`/`registry_change_publish`
// for registry changes) share the table cleanly without ever colliding.
//
// Kept separate from `NativeUserAction`: that type is the native consent routes' contract
// and should not grow.

import type { PrismaClient } from '@openkey/db';

const WINDOW_MS = 60 * 60_000; // 1 hour window

export type PerOwnerLimiter<Action extends string> = (
  subject: string,
  action: Action,
  now?: number,
) => Promise<number>;

/** Prisma-backed per-owner limiter (default in production). `UPSERT ... DO UPDATE SET count = count + 1`
 *  is the atomic path; after the increment the function checks whether the new count is within the limit
 *  and returns the `retry-after` seconds (or 0 when allowed). */
export function createPrismaPerOwnerLimiter<Action extends string>(
  prisma: PrismaClient,
  limits: Record<Action, number>,
  windowMs = WINDOW_MS,
): PerOwnerLimiter<Action> {
  return async (subject, action, now = Date.now()) => {
    const windowStartMs = Math.floor(now / windowMs) * windowMs;
    const id = `${action}:${subject.toLowerCase()}:${windowStartMs}`;
    const rows = await prisma.$queryRaw<{ count: number }[]>`
      INSERT INTO "tinycloud_setup_rate_limit_bucket" ("id", "action", "subject", "windowStartMs", "count", "updatedAt")
      VALUES (${id}, ${action}, ${subject.toLowerCase()}, ${BigInt(windowStartMs)}, 1, NOW())
      ON CONFLICT ("id") DO UPDATE SET "count" = "tinycloud_setup_rate_limit_bucket"."count" + 1, "updatedAt" = NOW()
      RETURNING "count";
    `;
    const count = rows[0]?.count ?? 0;
    if (count > limits[action]) {
      const resetAt = windowStartMs + windowMs;
      return Math.max(1, Math.ceil((resetAt - now) / 1_000));
    }
    return 0;
  };
}

/** In-memory per-owner limiter for unit tests + local dev. Mirrors the Prisma limiter shape. */
export function createInMemoryPerOwnerLimiter<Action extends string>(
  limits: Record<Action, number>,
  maxBuckets = 10_000,
  windowMs = WINDOW_MS,
): PerOwnerLimiter<Action> {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  return async (subject, action, now = Date.now()) => {
    const key = `${action}:${subject.toLowerCase()}`;
    const prior = buckets.get(key);
    const bucket = prior && prior.resetAt > now ? prior : { count: 0, resetAt: now + windowMs };
    if (bucket.count >= limits[action]) return Math.max(1, Math.ceil((bucket.resetAt - now) / 1_000));
    bucket.count++;
    buckets.delete(key);
    buckets.set(key, bucket);
    if (buckets.size > maxBuckets) buckets.delete(buckets.keys().next().value!);
    return 0;
  };
}

/** Per-owner actions the setup endpoint tracks. */
export type TinyCloudSetupAction = 'mint' | 'publish';

const DEFAULT_LIMITS: Record<TinyCloudSetupAction, number> = {
  mint: 10,      // at most 10 widget renders per owner per hour
  publish: 5,    // at most 5 publish attempts per owner per hour
};

export type TinyCloudSetupLimiter = PerOwnerLimiter<TinyCloudSetupAction>;

export function createPrismaTinyCloudSetupLimiter(
  prisma: PrismaClient,
  limits: Record<TinyCloudSetupAction, number> = DEFAULT_LIMITS,
): TinyCloudSetupLimiter {
  return createPrismaPerOwnerLimiter(prisma, limits);
}

export function createInMemoryTinyCloudSetupLimiter(
  limits: Record<TinyCloudSetupAction, number> = DEFAULT_LIMITS,
  maxBuckets = 10_000,
): TinyCloudSetupLimiter {
  return createInMemoryPerOwnerLimiter(limits, maxBuckets);
}
