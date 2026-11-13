/** A first session shows the welcome for this long; later it is just an account signed in. */
const WELCOME_WINDOW_MS = 30 * 60_000;
/** The server stamps a new user and its first session in one request: seconds apart at most. */
const SAME_REQUEST_MS = 60_000;

type SessionData = { session?: { createdAt?: unknown }; user?: { createdAt?: unknown } } | null | undefined;

function stamp(value: unknown): number {
  return typeof value === 'string' || typeof value === 'number' || value instanceof Date ? new Date(value).getTime() : NaN;
}

/**
 * True for the first session of a brand-new account. Compares the two server timestamps with each other (no
 * client/server clock skew); the client clock only ends the welcome after half an hour.
 */
export function isFirstSession(data: SessionData, now: number = Date.now()): boolean {
  const session = stamp(data?.session?.createdAt);
  const user = stamp(data?.user?.createdAt);
  if (Number.isNaN(session) || Number.isNaN(user)) return false;
  return Math.abs(session - user) <= SAME_REQUEST_MS && now - session <= WELCOME_WINDOW_MS;
}
