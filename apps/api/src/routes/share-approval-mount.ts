import { Hono } from 'hono';
import type { SessionContext } from '../middleware/session';

/** Mount behind requireShareApproval, before forwarding to the authenticated runtime. */
export function createShareApprovalMount(runtime: Hono<SessionContext>) {
  const router = new Hono<SessionContext>();
  router.get('/capabilities', c => {
    c.header('Access-Control-Allow-Origin', '*');
    c.header('Access-Control-Allow-Credentials', undefined);
    return c.json({ enabled: true, protocolVersion: 1 });
  });
  return router.route('/', runtime);
}
