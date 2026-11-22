import type { Env, Hono, MiddlewareHandler } from 'hono';

// Limits for Better Auth's email-code endpoints, keyed on the target email rather than the client address. The
// address Better Auth would use is the first `x-forwarded-for` entry, which a caller can choose freely, and every
// caller without the header arrives with the same proxy address; neither identifies a person.
//
// Counters live in this process's memory. That is correct for a single API instance; with several instances each
// enforces its own share.

type Rule = { max: number; windowSeconds: number };
type PathLimits = { perEmail: Rule[]; global: Rule };

const MINUTE = 60;
const HOUR = 60 * 60;

/** Better Auth paths (relative to its base path) this limiter owns. */
export const EMAIL_OTP_LIMITS: Readonly<Record<string, PathLimits>> = {
  '/email-otp/send-verification-otp': {
    perEmail: [{ max: 3, windowSeconds: MINUTE }, { max: 10, windowSeconds: HOUR }],
    global: { max: 120, windowSeconds: MINUTE },
  },
  '/email-otp/check-verification-otp': {
    perEmail: [{ max: 10, windowSeconds: MINUTE }],
    global: { max: 360, windowSeconds: MINUTE },
  },
  '/email-otp/verify-email': {
    perEmail: [{ max: 10, windowSeconds: MINUTE }],
    global: { max: 360, windowSeconds: MINUTE },
  },
  '/sign-in/email-otp': {
    perEmail: [{ max: 10, windowSeconds: MINUTE }],
    global: { max: 360, windowSeconds: MINUTE },
  },
};

/**
 * Better Auth `rateLimit.customRules` entries that switch off its address-keyed limit on the paths above, so only
 * the email-keyed limit applies to them.
 */
export const EMAIL_OTP_ADDRESS_LIMIT_OFF: Record<string, false> = Object.fromEntries(
  Object.keys(EMAIL_OTP_LIMITS).map((path) => [path, false]),
);

/** The response Better Auth's own limiter sends, so callers see one shape whichever limit applies. */
function tooManyRequests(retryAfterSeconds: number): Response {
  return new Response(JSON.stringify({ message: 'Too many requests. Please try again later.' }), {
    status: 429,
    statusText: 'Too Many Requests',
    headers: { 'X-Retry-After': retryAfterSeconds.toString() },
  });
}

/**
 * Better Auth's own answer to a body that is not JSON. Its router admits any content type whose base merely
 * contains `application/json` and may then parse the body as a form, which this limiter would not read; only an
 * exact `application/json` base passes here.
 */
function unsupportedMediaType(contentType: string): Response {
  const message = contentType
    ? `Content-Type "${contentType}" is not allowed. Allowed types: application/json`
    : 'Content-Type is required. Allowed types: application/json';
  return new Response(JSON.stringify({ message, code: 'UNSUPPORTED_MEDIA_TYPE' }), {
    status: 415,
    statusText: '415',
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Better Auth lowercases the email; trimming as well keeps whitespace variants of one address on one key. */
function normalizedEmail(body: unknown): string | null {
  if (!body || typeof body !== 'object' || Array.isArray(body) || !('email' in body)) return null;
  const email = body.email;
  if (typeof email !== 'string') return null;
  const normalized = email.trim().toLowerCase();
  return normalized === '' ? null : normalized;
}

type Bucket = { count: number; resetAt: number };

export function createEmailOtpRateLimit(options: {
  /** Better Auth's base path, e.g. `/api/auth`. */
  basePath: string;
  now?: () => number;
}): MiddlewareHandler {
  const now = options.now ?? Date.now;
  const basePath = options.basePath.replace(/\/+$/, '');
  const buckets = new Map<string, Bucket>();
  let nextPrune = 0;

  const prune = (at: number) => {
    if (at < nextPrune) return;
    for (const [key, bucket] of buckets) if (bucket.resetAt <= at) buckets.delete(key);
    nextPrune = at + MINUTE * 1000;
  };

  return async (c, next) => {
    if (c.req.method !== 'POST') return next();
    // Better Auth strips trailing slashes before matching its own limit rules; match the same way.
    const pathname = new URL(c.req.url).pathname.replace(/\/+$/, '');
    if (!pathname.startsWith(basePath + '/')) return next();
    const path = pathname.slice(basePath.length);
    const limits = EMAIL_OTP_LIMITS[path];
    if (!limits) return next();

    const contentType = c.req.header('content-type') ?? '';
    if (contentType.split(';')[0]!.trim().toLowerCase() !== 'application/json') return unsupportedMediaType(contentType);

    // Read from a clone so Better Auth receives the untouched body. A body Better Auth would refuse counts only
    // against the shared ceiling, and Better Auth's validation answers it.
    const email = normalizedEmail(await c.req.raw.clone().json().catch(() => null));
    const at = now();
    prune(at);

    const keyed: Array<[string, Rule]> = [[`global:${path}`, limits.global]];
    if (email) for (const rule of limits.perEmail) keyed.push([`email:${path}:${rule.windowSeconds}:${email}`, rule]);

    let retryAfter = 0;
    for (const [key, rule] of keyed) {
      const bucket = buckets.get(key);
      if (bucket && bucket.resetAt > at && bucket.count >= rule.max) {
        retryAfter = Math.max(retryAfter, Math.ceil((bucket.resetAt - at) / 1000));
      }
    }
    if (retryAfter > 0) return tooManyRequests(retryAfter);

    for (const [key, rule] of keyed) {
      const bucket = buckets.get(key);
      if (bucket && bucket.resetAt > at) bucket.count += 1;
      else buckets.set(key, { count: 1, resetAt: at + rule.windowSeconds * 1000 });
    }
    return next();
  };
}

/**
 * Mounts the limiter on Better Auth's `/api/auth` routes under the same condition as Better Auth's own limiter
 * (NODE_ENV=production), so local and test runs are unlimited. Call it before the auth handler is registered.
 */
export function mountEmailOtpRateLimit<E extends Env>(app: Hono<E>, nodeEnv: string | undefined, now?: () => number): void {
  if (nodeEnv !== 'production') return;
  app.use('/api/auth/*', createEmailOtpRateLimit({ basePath: '/api/auth', now }));
}
