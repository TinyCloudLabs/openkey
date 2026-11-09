import type { Context } from 'hono';
import { resolveOriginPolicy } from '../origin-policy';

/**
 * TinyCloud signing controls (signing mode, per-app grants, the primary key)
 * are deliberately cookie-session-only from an OpenKey browser origin. In
 * particular, an OAuth bearer token that can call /delegate/sign must never
 * change custody. Returns a 403 response to send, or null to continue.
 */
export function rejectNonBrowserControlRequest(c: Context) {
  if (c.req.header('authorization')) return c.json({ error: 'Bearer tokens cannot change TinyCloud signing controls' }, 403);
  const origin = c.req.header('origin');
  const allowed = resolveOriginPolicy('http://localhost:5173,http://localhost:3000');
  if (!origin || !allowed.includes(origin)) return c.json({ error: 'A same-site browser Origin is required' }, 403);
  return null;
}

/**
 * Managed-key signing routes accept a session only from an OpenKey web
 * origin: the session cookie is scoped to the whole site, so any sibling page
 * could otherwise send a signed-in user's browser here, and the caller could
 * then claim any requestOrigin it likes in the body. Bearer credentials get
 * the same answer — requireOpenKeyOriginForBearer already demands the same
 * origins, so this check is unconditional and does not depend on how the
 * router is mounted. Returns a 403 response to send, or null to continue.
 */
export function rejectNonOpenKeySignRequest(c: Context) {
  const origin = c.req.header('origin');
  const allowed = resolveOriginPolicy('http://localhost:5173,http://localhost:3000');
  if (!origin || !allowed.includes(origin)) return c.json({ error: 'Managed-key signing requires an OpenKey browser origin' }, 403);
  return null;
}

