import { logReviewer } from '../log';
import { provisionReviewer } from '../services/reviewer-fixtures';
import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import type { PrismaClient } from '@openkey/db';
import {
  REVIEWER_STORES, adminCredentialMatches, installReviewer, reviewerStatus, unsetReviewer, pinReviewerAudience,
} from '../services/reviewer-accounts';

export function createReviewerAdminRouter(database: PrismaClient) {
  const router = new Hono();
  router.use('*', bodyLimit({ maxSize: 4096 }));
  router.use('*', async (c, next) => {
    const expected = process.env.ADMIN_API_KEY;
    const authorization = c.req.header('authorization');
    if (!expected) return c.json({ error: 'Admin API not configured' }, 503);
    if (!authorization?.startsWith('Bearer ') || !adminCredentialMatches(authorization.slice(7), expected)) {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    c.header('Cache-Control', 'no-store');
    await next();
  });
  router.get('/', async (c) => {
    const bindings = await database.reviewerAccount.findMany({ include: { user: true }, orderBy: { store: 'asc' } });
    return c.json({ accounts: bindings.map(reviewerStatus) });
  });
  router.use('/:store/*', async (c, next) => {
    if (!REVIEWER_STORES.includes(c.req.param('store') as typeof REVIEWER_STORES[number])) {
      return c.json({ error: 'Unknown reviewer store' }, 404);
    }
    await next();
  });
  router.post('/:store/provision', async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body || Object.keys(body).some((key) => !['clientId', 'nodeHost', 'reset'].includes(key))
      || typeof body.clientId !== 'string' || typeof body.nodeHost !== 'string'
      || (body.reset !== undefined && typeof body.reset !== 'boolean')) {
      return c.json({ error: 'Reviewer configuration refused' }, 400);
    }
    try { await provisionReviewer(database, c.req.param('store'), body, body.reset === true); }
    catch { return c.json({ error: 'Reviewer provisioning did not complete' }, 400); }
    return c.json({ provisioned: true });
  });
  router.put('/:store/audience', async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body || Object.keys(body).some((key) => key !== 'sessionDid')
      || !(body.sessionDid === null || typeof body.sessionDid === 'string')) {
      return c.json({ error: 'Reviewer audience refused' }, 400);
    }
    try { await pinReviewerAudience(database, c.req.param('store'), body.sessionDid); }
    catch { return c.json({ error: 'Reviewer audience refused' }, 400); }
    return c.json({ pinned: body.sessionDid !== null, set: false });
  });
  router.put('/:store/ready', async (c) => {
    const body = await c.req.json().catch(() => null);
    const binding = await database.reviewerAccount.findUnique({ where: { store: c.req.param('store') }, include: { user: true } });
    if (body?.seededReadVerified !== true || !binding || binding.store === 'apple' || !binding.sessionDid
      || !binding.seededAt || !binding.grantSessionId || !reviewerStatus(binding).set) {
      return c.json({ error: 'Reviewer readiness is incomplete' }, 400);
    }
    const updated = await database.reviewerAccount.updateMany({
      where: { store: binding.store, installEpoch: binding.installEpoch, grantSessionId: binding.grantSessionId },
      data: { readyAt: new Date() },
    });
    if (updated.count !== 1) return c.json({ error: 'Reviewer readiness was superseded' }, 409);
    logReviewer('reviewer_admin', 'ready', binding.store);
    return c.json({ ready: true });
  });
  router.put('/:store/code', async (c) => {
    if (c.req.header('content-type')?.split(';')[0]?.trim() !== 'application/json') {
      return c.json({ error: 'JSON is required' }, 400);
    }
    const body = await c.req.json().catch(() => null) as { code?: unknown } | null;
    try { await installReviewer(database, c.req.param('store'), body?.code); }
    catch { return c.json({ error: 'Reviewer account or code is not ready' }, 400); }
    return c.json({ set: true });
  });
  router.delete('/:store/code', async (c) => {
    await unsetReviewer(database, c.req.param('store'));
    return c.json({ set: false });
  });
  return router;
}
