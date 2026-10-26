// An absolute cap on OpenKey web sign-in sessions.
//
// A web session lasts 7 days (`session.expiresIn`) and every use after 24 hours
// (`session.updateAge`) pushes its expiry out another 7 days, so a session that is
// used regularly never ends. This caps it: a refresh can move `expiresAt` no later
// than `createdAt` plus the cap, so every web session ends at most 30 days after the
// sign-in that created it. Signing in again creates a new session with a new
// `createdAt`.

import { log } from '../log';

/** The most a web session may live, counted from the sign-in that created it. */
export const WEB_SESSION_ABSOLUTE_CAP_SECONDS = 60 * 60 * 24 * 30;
const CAP_MS = WEB_SESSION_ABSOLUTE_CAP_SECONDS * 1000;

/** The part of Better Auth's hook context this reads: the session of the request being refreshed. */
export interface SessionRefreshContext {
  context?: { session?: { session?: { createdAt?: unknown } | null } | null } | null;
}

/** A time in milliseconds from a Date, an ISO string or epoch milliseconds; NaN for anything else (null included). */
function timeMs(value: unknown): number {
  if (value instanceof Date) return value.getTime();
  return typeof value === 'string' || typeof value === 'number' ? new Date(value).getTime() : Number.NaN;
}

/**
 * `databaseHooks.session.update.before`. Better Auth runs it with only the changed fields
 * (`{ expiresAt, updatedAt }` on the refresh-on-use path of `/get-session`); the session row
 * being refreshed is `context.context.session`, set by `/get-session` just before it refreshes.
 *
 * - Not an expiry change: left alone.
 * - Expiry later than `createdAt + cap`: set to `createdAt + cap`. For a session already older
 *   than the cap that is a time in the past, so the session ends now and is not extended.
 * - `createdAt` unknown or the new expiry unreadable: the update is refused (the cap cannot be
 *   applied, so nothing is extended) and a warning is logged.
 */
export async function capSessionRefresh(
  data: { expiresAt?: unknown },
  context: SessionRefreshContext | null,
): Promise<{ data: { expiresAt: Date } } | false | undefined> {
  if (data.expiresAt === undefined) return undefined;
  const requested = timeMs(data.expiresAt);
  const createdAt = timeMs(context?.context?.session?.session?.createdAt);
  if (!Number.isFinite(requested) || !Number.isFinite(createdAt)) {
    log('warn', 'session_cap_unapplied');
    return false;
  }
  const latest = createdAt + CAP_MS;
  return requested > latest ? { data: { expiresAt: new Date(latest) } } : undefined;
}
