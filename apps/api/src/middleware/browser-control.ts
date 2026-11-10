import type { Context } from 'hono';
import { isAccountOriginAllowed, resolveSigningOriginPolicy } from '../origin-policy';
import { logSignOriginRefused } from '../log';

/**
 * TinyCloud signing controls (signing mode, per-app grants, the primary key)
 * are deliberately cookie-session-only from an OpenKey browser origin. In
 * particular, an OAuth bearer token that can call /delegate/sign must never
 * change custody. Returns a 403 response to send, or null to continue.
 */
export function rejectNonBrowserControlRequest(c: Context) {
  if (c.req.header('authorization')) return c.json({ error: 'Bearer tokens cannot change TinyCloud signing controls' }, 403);
  const origin = c.req.header('origin');
  if (!isAccountOriginAllowed(origin, 'http://localhost:5173,http://localhost:3000')) return c.json({ error: 'A same-site browser Origin is required' }, 403);
  return null;
}

/**
 * Managed-key signing routes must not accept the shared session cookie from
 * the console host: a sibling page could otherwise sign for the user and
 * claim any requestOrigin it likes in the body. On /api/delegate/sign this
 * guard applies only to cookie-session requests; OAuth bearer requests use a
 * separate path. Returns a 403 response to send, or null to continue.
 */
export function rejectNonOpenKeySignRequest(c: Context) {
  const origin = c.req.header('origin');
  const allowed = resolveSigningOriginPolicy('http://localhost:5173,http://localhost:3000');
  if (!origin || !allowed.includes(origin)) {
    logSignOriginRefused(c.req.routePath, origin ? 'foreign' : 'missing');
    return c.json({ error: 'Managed-key signing requires an OpenKey browser origin' }, 403);
  }
  return null;
}

