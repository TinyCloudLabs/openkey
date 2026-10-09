const WINDOW_MS = 60_000;
export type NativeUserAction = 'authorize' | 'prepare' | 'approve' | 'deny';
const DEFAULT_LIMITS: Record<NativeUserAction, number> = {
  authorize: 120,
  prepare: 60,
  approve: 30,
  deny: 30,
};

/** These requests carry a verified OpenKey session, so one anonymous caller
 * cannot spend another user's budget. Each action has its own budget so a
 * burst of previews cannot prevent the user from approving or denying. */
export function createNativeUserLimiter(limits: Record<NativeUserAction, number> = DEFAULT_LIMITS, maxBuckets = 10_000) {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  return (userId: string, action: NativeUserAction, now = Date.now()): number => {
    const key = `${action}:${userId}`;
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

export const nativeUserRetryAfter = createNativeUserLimiter();
