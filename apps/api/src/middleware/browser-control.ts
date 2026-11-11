import type { Context } from 'hono';
import { isAccountOriginAllowed } from '../origin-policy';
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
 * Cookie-session signing is limited to the configured account origin. OAuth
 * bearer requests use their separate signer path and do not call this helper.
 */
export function rejectNonOpenKeySignRequest(c: Context) {
  if (!isAccountOriginAllowed(c.req.header('origin'), 'http://localhost:5173,http://localhost:3000')) {
    logSignOriginRefused(c.req.routePath, c.req.header('origin') ? 'foreign' : 'missing');
    return c.json({ error: 'Managed-key signing requires an OpenKey browser origin' }, 403);
  }
  return null;
}
