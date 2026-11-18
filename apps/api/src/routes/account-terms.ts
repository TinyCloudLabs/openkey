import { Hono } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { auth } from '../auth';
import { requireAccountOriginForBearer } from '../middleware/bearer-origin';
import { requireSessionBeforeTerms, type SessionContext } from '../middleware/session';
import { hasAcceptedTerms, recordTermsAcceptance, termsRelease, termsStatus } from '../services/terms';
import { stopRenewalsOnDecline } from '../services/terms-decline';

/**
 * TC-3232: the required Terms screen's calls. Mounted ahead of the account router, whose session check
 * refuses an account that has not accepted; these routes are what it accepts or declines with. Both are
 * answered only from the browser (cookie session): a session token (widget, CLI) can't stand in for a person.
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
    if (c.req.header('authorization')) return c.json({ error: 'Terms are accepted in the browser' }, 403);
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

  // Don't agree: the account's renewals stop at the node (best effort, within a budget), then this session signs
  // out. Only while the account has a version to accept; stopping never keeps the person signed in.
  router.post('/decline', async (c) => {
    if (c.req.header('authorization')) return c.json({ error: 'Terms are declined in the browser' }, 403);
    const userId = c.get('user').id;
    if (await hasAcceptedTerms(database, userId)) return c.json({ error: 'terms_not_required' }, 409);
    const renewals = await stopRenewalsOnDecline(database, userId);
    const signedOut = await auth.api.signOut({ headers: c.req.raw.headers, asResponse: true });
    for (const cookie of signedOut.headers.getSetCookie()) c.header('set-cookie', cookie, { append: true });
    if (!signedOut.ok) return c.json({ error: 'sign_out_failed', renewals }, 500);
    return c.json({ signedOut: true, renewals });
  });

  return router;
}
