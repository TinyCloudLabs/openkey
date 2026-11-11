import { Hono, type Context, type MiddlewareHandler } from 'hono';
import type { PrismaClient } from '@openkey/db';
import type { SessionContext } from '../middleware/session';
import { isOrgKeyCustodyEnabled, OrgKeyRefusal } from '../services/org-keys';
import { acceptAdmin, adminRoster, revokeAdmin, maskedInvitation, pendingInvitations, invitationSummary, inviteAdmin, type GrantAssertion, type InviteTarget } from '../services/org-key-admins';
import { invitationEmailDelivery } from '../services/org-key-invitation-email';
import type { GrantActor } from '../services/org-key-grant-challenge';

type Deps = { prisma: PrismaClient; sessionMiddleware: MiddlewareHandler<SessionContext>; webauthn: () => { rpID: string; origin: string } };
function router(deps: Deps, paths: string[] = ['*']) {
  const app = new Hono<SessionContext>();
  for (const path of paths) {
  app.use(path, async (c, next) => {
    if (!isOrgKeyCustodyEnabled()) return c.json({ error: 'Not found' }, 404);
    // These operations require a first-party cookie session, never bearer tokens.
    if (c.req.header('authorization')) return c.json({ error: 'Forbidden' }, 403);
    if (c.req.method !== 'GET' && c.req.header('origin') !== deps.webauthn().origin) return c.json({ error: 'Forbidden' }, 403);
    return next();
  });
  app.use(path, deps.sessionMiddleware);
  }
  app.onError((error, c) => {
    if (error instanceof OrgKeyRefusal) return c.json({ error: error.message, code: error.code }, error.status);
    throw error;
  });
  return app;
}
function actor(c: Context<SessionContext>, deps: Deps): GrantActor {
  const relyingParty = deps.webauthn();
  if (!relyingParty.rpID || !relyingParty.origin) throw new OrgKeyRefusal(403, 'grant_origin_invalid', 'Forbidden');
  return { userId: c.get('user').id, sessionId: c.get('session').id, origin: relyingParty.origin, rpId: relyingParty.rpID };
}
async function body(c: Context): Promise<Record<string, unknown>> {
  if (Number(c.req.header('content-length') ?? 0) > 32_768) throw new OrgKeyRefusal(400, 'grant_request_invalid', 'Forbidden');
  try {
    const raw = await c.req.text();
    if (raw.length > 32_768) throw new Error();
    const value = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch { throw new OrgKeyRefusal(400, 'grant_request_invalid', 'Forbidden'); }
}
function proof(value: Record<string, unknown>): GrantAssertion {
  if (typeof value.nonce !== 'string' || !value.assertion || typeof value.assertion !== 'object') throw new OrgKeyRefusal(400, 'grant_request_invalid', 'Forbidden');
  return { nonce: value.nonce, assertion: value.assertion as GrantAssertion['assertion'] };
}
export function createOrgKeyAdminsRouter(deps: Deps) {
  const app = router(deps, ['/:keyId/admins', '/:keyId/admins/*', '/:keyId/admin-invitations', '/:keyId/admin-invitations/*']);
  app.get('/:keyId/admins', async c => c.json(await adminRoster(deps.prisma, c.get('user').id, c.req.param('keyId'))));
  for (const challenge of [true, false]) {
    app.post(`/:keyId/admin-invitations${challenge ? '/challenge' : ''}`, async c => {
      const value = await body(c);
      if (Object.keys(value).some(k => !['email', 'accountId', ...(challenge ? [] : ['nonce', 'assertion'])].includes(k))) throw new OrgKeyRefusal(400, 'grant_request_invalid', 'Forbidden');
      if (('email' in value && typeof value.email !== 'string') || ('accountId' in value && typeof value.accountId !== 'string')) throw new OrgKeyRefusal(400, 'grant_request_invalid', 'Forbidden');
      const target: InviteTarget = { email: typeof value.email === 'string' ? value.email : undefined, accountId: typeof value.accountId === 'string' ? value.accountId : undefined };
      return c.json(await inviteAdmin(deps.prisma, actor(c, deps), c.req.param('keyId'), target, challenge ? undefined : proof(value), invitationEmailDelivery(deps.prisma)));
    });
  }
  for (const challenge of [true, false]) {
    app.post(`/:keyId/admins/:grantId/${challenge ? 'revoke-challenge' : 'revoke'}`, async c => {
      const value = await body(c);
      if (Object.keys(value).some(k => !(challenge ? [] : ['nonce', 'assertion']).includes(k))) throw new OrgKeyRefusal(400, 'grant_request_invalid', 'Forbidden');
      return c.json(await revokeAdmin(deps.prisma, actor(c, deps), c.req.param('keyId'), c.req.param('grantId'), challenge ? undefined : proof(value)));
    });
  }
  return app;
}
export function createOrgKeyInvitationsRouter(deps: Deps) {
  const app = router(deps);
  app.get('/', async c => c.json({ invitations: await pendingInvitations(deps.prisma, c.get('user').id) }));
  app.get('/:id', async c => {
    try { return c.json(await invitationSummary(deps.prisma, actor(c, deps), c.req.param('id'))); }
    catch (error) {
      if (!(error instanceof OrgKeyRefusal)) throw error;
      return c.json(await maskedInvitation(deps.prisma, c.req.param('id'), c.req.header('x-invitation-token')));
    }
  });
  for (const challenge of [true, false]) {
    app.post(`/:id/${challenge ? 'accept-challenge' : 'accept'}`, async c => {
      const value = await body(c);
      if (Object.keys(value).some(k => ! (challenge ? [] : ['nonce', 'assertion']).includes(k))) throw new OrgKeyRefusal(400, 'grant_request_invalid', 'Forbidden');
      return c.json(await acceptAdmin(deps.prisma, actor(c, deps), c.req.param('id'), challenge ? undefined : proof(value)));
    });
  }
  return app;
}
