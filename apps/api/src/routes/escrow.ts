import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import type { createOpenKeyEscrowService } from '../services/escrow-service';

type Service = ReturnType<typeof createOpenKeyEscrowService>;
/** No shared API key/session bypass; each operation verifies its device signatures. */
export function createEscrowRouter(service: Service) {
  const router = new Hono();
  router.use('*', async (c, next) => {
    c.header('Cache-Control', 'no-store');
    if (service.enabled() !== true) return c.json({ error: 'Not found' }, 404);
    return next();
  });
  router.use('*', bodyLimit({ maxSize: 64 * 1024 }));
  router.get('/configuration', c => c.json({ measuredConfigHash: service.measuredConfigHash }));
  router.post('/preflight', async c => {
    try {
      const body = await c.req.json();
      if (!body || Object.keys(body).sort().join(',') !== 'approval,approverId') throw new Error('Invalid request');
      return c.json(await service.preflight(body));
    } catch { return c.json({ error: 'escrow_refused' }, 403); }
  });
  router.post('/export', async c => {
    try {
      const body = await c.req.json();
      if (!body || Object.keys(body).join(',') !== 'approval') throw new Error('Invalid request');
      return c.json(await service.export(body));
    } catch { return c.json({ error: 'escrow_refused' }, 403); }
  });
  return router;
}
