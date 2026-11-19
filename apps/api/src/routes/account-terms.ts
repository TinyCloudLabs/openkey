import { Hono } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { requireAccountOriginForBearer } from '../middleware/bearer-origin';
import { requireSessionBeforeTerms, type SessionContext } from '../middleware/session';
import { recordTermsAcceptance, termsRelease, termsStatus } from '../services/terms';

/**
 * TC-3232: the required Terms screen's two calls. Mounted ahead of the account router, whose session check
 * refuses an account that has not accepted; these routes are what it accepts with.
 */
export function createAccountTermsRouter(database: PrismaClient) {
  const router = new Hono<SessionContext>();
  router.use('*', requireAccountOriginForBearer);
  router.use('*', requireSessionBeforeTerms);

  router.get('/', async (c) => {
    c.header('Cache-Control', 'no-store');
    return c.json(await termsStatus(database, c.get('user').id, termsRelease()));
  });

  // Only the version the screen showed, and only while it is current, is recorded.
  router.post('/accept', async (c) => {
    const body = await c.req.json().catch(() => null) as { version?: unknown; surface?: unknown; clientId?: unknown } | null;
    const release = termsRelease();
    if (!release || body?.version !== release.version) {
      return c.json({ error: 'terms_version_mismatch', version: release?.version ?? null }, 409);
    }
    let surface = 'web';
    if (body.surface === 'native') {
      const client = typeof body.clientId === 'string'
        ? await database.oauthClient.findUnique({ where: { clientId: body.clientId }, select: { clientId: true } })
        : null;
      if (!client) return c.json({ error: 'invalid_request' }, 400);
      surface = `native:${client.clientId}`;
    } else if (body.surface !== undefined && body.surface !== 'web') {
      return c.json({ error: 'invalid_request' }, 400);
    }
    await recordTermsAcceptance(database, c.get('user').id, release, surface);
    return c.json({ accepted: true, version: release.version });
  });

  return router;
}
