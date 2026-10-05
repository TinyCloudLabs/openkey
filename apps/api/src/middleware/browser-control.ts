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
