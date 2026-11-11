import { reviewerSeedGrant, verifyReviewerSeed } from '../services/reviewer-apple-seed';
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
    if (!body || Object.keys(body).some((key) => !['clientId', 'nodeHost', 'reset', 'redirectUri'].includes(key))
      || (body.redirectUri !== undefined && typeof body.redirectUri !== 'string')
      || typeof body.clientId !== 'string' || typeof body.nodeHost !== 'string'
      || (body.reset !== undefined && typeof body.reset !== 'boolean')) {
      return c.json({ error: 'Reviewer configuration refused' }, 400);
    }
    try { await provisionReviewer(database, c.req.param('store'), body, body.reset === true); }
    catch { return c.json({ error: 'Reviewer provisioning did not complete' }, 400); }
    return c.json({ provisioned: true });
  });
  router.get('/apple/seed-target', async c => {
    const { appleReviewEnabled } = await import('../services/reviewer-apple-policy');
    const binding = await database.reviewerAccount.findUnique({ where: { store: 'apple' }, include: { user: true } });
    const key = binding?.keyId ? await database.ethereumKey.findFirst({ where: { id: binding.keyId, userId: binding.userId } }) : null;
    if (!appleReviewEnabled() || !binding?.user?.reviewerHoldAt || binding.seededAt || !binding.spaceId || !binding.nodeHost || !key) return c.json({ error: 'Reviewer seed unavailable' }, 400);
    return c.json({ spaceId: binding.spaceId, ownerDid: `did:pkh:eip155:1:${key.address}`, nodeHost: binding.nodeHost });
  });
  router.post('/apple/seed-grant', async c => {
    const body = await c.req.json().catch(() => null);
    if (!body || Object.keys(body).some(key => !['request', 'dryRun'].includes(key)) || typeof body.dryRun !== 'boolean') return c.json({ error: 'Reviewer seed request refused' }, 400);
    try { return c.json(await reviewerSeedGrant(database, body.request, body.dryRun)); }
    catch { return c.json({ error: 'Reviewer seed request refused' }, 400); }
  });
  router.post('/apple/seed-verify', async c => {
    const body = await c.req.json().catch(() => null);
    if (!body || Object.keys(body).some(key => key !== 'report')) return c.json({ error: 'Reviewer seed verification refused' }, 400);
    try { await verifyReviewerSeed(database, body.report); }
    catch { return c.json({ error: 'Reviewer seed verification refused' }, 400); }
    return c.json({ seeded: true });
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
    if (!binding || (binding.store === 'apple'
      ? body?.homeReadVerified !== true || body?.deletionVerified !== true
      : body?.seededReadVerified !== true || !binding.sessionDid)
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
