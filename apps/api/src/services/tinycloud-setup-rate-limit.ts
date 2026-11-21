// TC-3657 Bobbie C5 + N3 (14:32:09Z, 14:53:16Z): per-owner rate limit on
// `/authorize-tinycloud-setup`. The SDK-side 24h throttle in `localStorage`
// (js-sdk#1113 `handle-account-setup-required.ts`) is UX-only; the outside
// app owns its own storage. THIS limiter is the security guarantee.
//
// Shape mirrors `native-delegation/user-rate-limit.ts` so the operator can
// reason about both limits the same way. Separate module (not a widened
// `NativeUserAction`) per OpenKey driver 15:01:13Z — the native type is the
// native consent routes' contract and should not grow to carry TC-3657
// actions.
//
// [INFERENCE] In-process and per-API-instance; with >1 API replica the
// effective limit multiplies. If exactness matters in production, a
// follow-up should switch to a DB-backed counter sharing the owner-scope
// of `tinycloud-setup-ticket.ts`'s eventual Prisma store. Flagged in the
// design note.

const WINDOW_MS = 60 * 60_000; // 1 hour window

/** Per-owner actions the setup endpoint tracks. `mint` is the ticket mint call
 *  (owner lands on the widget page); `publish` is the POST consuming a ticket. */
export type TinyCloudSetupAction = 'mint' | 'publish';

const DEFAULT_LIMITS: Record<TinyCloudSetupAction, number> = {
  // A well-behaved outside app uses one of each per owner per day (Naomi's 24h
  // throttle). The hourly server limit is set tighter than the SDK throttle so a
  // compromised outside app with a cleared localStorage can't drive OpenKey into
  // a prompt loop faster than the owner can reasonably respond.
  mint: 10,      // at most 10 widget renders per owner per hour
  publish: 5,    // at most 5 publish attempts per owner per hour
};

export function createTinyCloudSetupLimiter(
  limits: Record<TinyCloudSetupAction, number> = DEFAULT_LIMITS,
  maxBuckets = 10_000,
) {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  /** Returns 0 when the call is admitted, or a positive retry-after in SECONDS otherwise. */
  return (subject: string, action: TinyCloudSetupAction, now = Date.now()): number => {
    const key = `${action}:${subject.toLowerCase()}`;
    const prior = buckets.get(key);
    const bucket = prior && prior.resetAt > now ? prior : { count: 0, resetAt: now + WINDOW_MS };
    if (bucket.count >= limits[action]) return Math.max(1, Math.ceil((bucket.resetAt - now) / 1_000));
    bucket.count++;
    buckets.delete(key); // LRU: re-insert to keep this entry warm.
    buckets.set(key, bucket);
    if (buckets.size > maxBuckets) buckets.delete(buckets.keys().next().value!);
    return 0;
  };
}

/** Shared process-wide default limiter used by the route. Tests construct their own via
 *  `createTinyCloudSetupLimiter` to assert thresholds without affecting production state. */
export const tinyCloudSetupRetryAfter = createTinyCloudSetupLimiter();
