import { Hono, type Context } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { createPrismaClient } from '@openkey/db';
import { requireOpenKeyOriginForBearer } from '../middleware/bearer-origin';
import { requireSession, type SessionContext } from '../middleware/session';
import { PreparedHandoffError, PreparedHandoffService } from '../services/prepared-handoff';
import { createPrismaPreparedHandoffStore } from '../services/prepared-handoff-store';

type Variables = SessionContext;

export const preparedHandoffService = new PreparedHandoffService(createPrismaPreparedHandoffStore(createPrismaClient()));

async function jsonRequest(c: Context<Variables>): Promise<unknown> {
  try {
    return await c.req.json();
  } catch {
    throw new PreparedHandoffError('invalid_request', 'Invalid JSON request', 400);
  }
}


export function createPreparedHandoffRouter(service: PreparedHandoffService = preparedHandoffService) {
  const router = new Hono<Variables>();

  router.onError((error, c) => {
    if (error instanceof PreparedHandoffError) return c.json({ code: error.code, error: error.message }, error.status);
    throw error;
  });

  router.post('/', bodyLimit({
    maxSize: 64 * 1024,
    onError: (c) => c.json({ code: 'invalid_request', error: 'Handoff request exceeds 64 KiB' }, 400),
  }), async (c) => {
    const raw = await c.req.text();
    if (Buffer.byteLength(raw, 'utf8') > 64 * 1024) {
      throw new PreparedHandoffError('invalid_request', 'Handoff request exceeds 64 KiB', 400);
    }
    let body: unknown;
    try { body = JSON.parse(raw); } catch { throw new PreparedHandoffError('invalid_request', 'Invalid JSON request', 400); }
    const ip = c.req.header('cf-connecting-ip') ?? c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
    return c.json(await service.start(body, ip), 201);
  });

  router.post('/resolve', requireOpenKeyOriginForBearer, requireSession, async (c) => {
    const body = await jsonRequest(c);
    if (!body || typeof body !== 'object' || !('ticket' in body) || typeof body.ticket !== 'string') {
      throw new PreparedHandoffError('invalid_request', 'ticket is required', 400);
    }
    return c.json(await service.resolve(body.ticket, c.get('user').id));
  });

  router.post('/cancel-claimed', requireOpenKeyOriginForBearer, requireSession, async (c) => {
    const body = await jsonRequest(c);
    if (!body || typeof body !== 'object' || !('ticket' in body) || typeof body.ticket !== 'string') {
      throw new PreparedHandoffError('invalid_request', 'ticket is required', 400);
    }
    await service.cancelClaimed(body.ticket, c.get('user').id);
    return c.json({ cancelled: true });
  });

  // CLI-only credential. No session and no result-reading endpoint.
  router.post('/cancel', async (c) => {
    const body = await jsonRequest(c);
    if (!body || typeof body !== 'object' || !('ticket' in body) || typeof body.ticket !== 'string' ||
      !('cancelSecret' in body) || typeof body.cancelSecret !== 'string') {
      throw new PreparedHandoffError('invalid_request', 'ticket and cancelSecret are required', 400);
    }
    await service.cancel(body.ticket, body.cancelSecret);
    return c.json({ cancelled: true });
  });

  return router;
}

export const preparedHandoffRouter = createPreparedHandoffRouter();
