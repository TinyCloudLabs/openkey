// An absolute cap on OpenKey web sign-in sessions.
//
// A web session lasts 7 days (`session.expiresIn`) and every use after 24 hours
// (`session.updateAge`) pushes its expiry out another 7 days, so a session that is
// used regularly never ends. This caps it: a refresh can move `expiresAt` no later
// than `createdAt` plus the cap, so every web session ends at most 30 days after the
// sign-in that created it. Signing in again creates a new session with a new
// `createdAt`.

import type { BetterAuthPlugin } from 'better-auth';
import { createAuthMiddleware } from 'better-auth/api';
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
 * - `createdAt` unknown or the new expiry unreadable: the cap cannot be applied, so the session
 *   is ended (its expiry is set to now) and a warning is logged. The update is not refused:
 *   a refused update makes `/get-session` answer 401 and `requireSession` routes answer 500
 *   while the row stays, and an ended session is the same result for every caller.
 */
export async function capSessionRefresh(
  data: { expiresAt?: unknown },
  context: SessionRefreshContext | null,
): Promise<{ data: { expiresAt: Date } } | undefined> {
  if (data.expiresAt === undefined) return undefined;
  const requested = timeMs(data.expiresAt);
  const createdAt = timeMs(context?.context?.session?.session?.createdAt);
  if (!Number.isFinite(requested) || !Number.isFinite(createdAt)) {
    log('warn', 'session_cap_unapplied');
    return { data: { expiresAt: new Date() } };
  }
  const latest = createdAt + CAP_MS;
  return requested > latest ? { data: { expiresAt: new Date(latest) } } : undefined;
}

/**
 * Since 1.6.35 Better Auth gives a refreshed session cookie the full `session.expiresIn` as Max-Age,
 * whatever expiry the hook above (or the reviewer cap) set, on `/get-session` and on any endpoint
 * whose session read refreshed it. This after hook, on every endpoint, brings the cookie's Max-Age
 * back to the session's own remaining lifetime, as before: a capped session's cookie ends with it,
 * and an ended session's cookie gets no positive lifetime. Only a cookie carrying that session's
 * token is changed; a cookie for another session (a new sign-in) is left as it is.
 */
export function sessionCookieCapPlugin() {
  return {
    id: 'openkey-session-cookie-cap',
    hooks: {
      after: [{
        matcher: () => true,
        handler: createAuthMiddleware(async (ctx) => {
          const headers = ctx.context.responseHeaders;
          const cookies = headers?.getSetCookie() ?? [];
          const prefix = ctx.context.authCookies.sessionToken.name + '=';
          if (!headers || !cookies.some((cookie) => cookie.startsWith(prefix))) return;
          type Read = { session?: { token?: unknown; expiresAt?: unknown } } | null | undefined;
          // `/get-session` returns the session as refreshed; elsewhere the endpoint's session read left it in the context.
          const sessions = [ctx.context.returned as Read, ctx.context.session as Read].map((read) => read?.session);
          let changed = false;
          const capped = cookies.map((cookie) => {
            if (!cookie.startsWith(prefix)) return cookie;
            const value = decodeURIComponent(cookie.slice(prefix.length).split(';', 1)[0]!);
            const token = value.slice(0, value.lastIndexOf('.'));
            const expiresAt = timeMs(sessions.find((session) => token && session?.token === token)?.expiresAt);
            if (!Number.isFinite(expiresAt)) return cookie;
            const remaining = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
            changed = true;
            return cookie.replace(/Max-Age=(\d+)/i, (_, age: string) => `Max-Age=${Math.min(Number(age), remaining)}`);
          });
          if (!changed) return;
          headers.delete('set-cookie');
          for (const cookie of capped) headers.append('set-cookie', cookie);
        }),
      }],
    },
  } satisfies BetterAuthPlugin;
}
