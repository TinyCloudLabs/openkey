import { randomBytes } from 'node:crypto';
import { Hono, type Context, type MiddlewareHandler } from 'hono';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { getAddress } from 'viem';
import { requireSession, type SessionContext } from '../middleware/session';
import { resolvePlanEntitlements, serializeEntitlements } from '../services/plan-entitlements';
import {
  oauthApplicationType,
  validateOAuthClientMetadataUrl,
  validateOAuthRedirectUris,
  type OAuthApplicationType,
} from '../services/oauth-redirect-uris';

type ConsoleMembership = { id: string; organizationId: string; userId: string; role: 'ADMIN' | 'MEMBER' };
type TenantConsoleContext = SessionContext & { Variables: SessionContext['Variables'] & { consoleMembership: ConsoleMembership } };
type TenantConsoleDependencies = { sessionMiddleware?: MiddlewareHandler<SessionContext> };
class ConsolePlanLimitError extends Error {}
class ConsoleMemberLimitError extends Error {}
class ConsoleMemberAlreadyExistsError extends Error {}

const APP_SELECT = {
  id: true, clientId: true, name: true, uri: true, icon: true, redirectUris: true,
  scopes: true, type: true, public: true, tokenEndpointAuthMethod: true, grantTypes: true,
  responseTypes: true, tinycloudSessionPolicy: true, tinycloudSessionOrigin: true,
  disabled: true, createdAt: true, updatedAt: true,
} as const;
const MEMBER_SELECT = {
  id: true, role: true, validFrom: true, createdAt: true,
  user: { select: { id: true, email: true, name: true } },
} as const;

function error(c: Context, status: 400 | 403 | 404 | 409 | 429, code: string, message: string) {
  return c.json({ error: { code, message } }, status);
}
function isAdmin(c: Context<TenantConsoleContext>) { return c.get('consoleMembership').role === 'ADMIN'; }
function activeMembershipWhere(organizationId: string, now: Date) {
  return { organizationId, status: 'ACTIVE' as const, revokedAt: null, validFrom: { lte: now }, OR: [{ validUntil: null }, { validUntil: { gt: now } }] };
}
function presentMember(member: { id: string; role: 'ADMIN' | 'MEMBER'; validFrom: Date; createdAt: Date; user: { id: string; email: string; name: string | null } }) {
  return { id: member.id, userId: member.user.id, email: member.user.email, name: member.user.name, role: member.role, validFrom: member.validFrom, createdAt: member.createdAt };
}
function parseAppInput(body: Record<string, unknown>, partial = false, current?: { type: string | null; redirectUris: string[] }) {
  const data: { name?: string; redirectUris?: string[]; uri?: string | null; icon?: string | null; type?: 'native' | 'spa'; disabled?: boolean } = {};
  if (!partial || body.name !== undefined) {
    if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 100) return null;
    data.name = body.name.trim();
  }
  let applicationType: OAuthApplicationType = current ? oauthApplicationType(current.type) : 'spa';
  if (body.uri !== undefined) { if (body.uri !== null && body.uri !== '' && !validateOAuthClientMetadataUrl(body.uri).valid) return null; data.uri = body.uri ? body.uri as string : null; }
  if (body.icon !== undefined) { if (body.icon !== null && body.icon !== '' && !validateOAuthClientMetadataUrl(body.icon).valid) return null; data.icon = body.icon ? body.icon as string : null; }
  if (body.type !== undefined) { if (body.type !== 'native' && body.type !== 'spa') return null; data.type = body.type; applicationType = body.type; }
  const effectiveRedirectUris = body.redirectUris ?? current?.redirectUris;
  if (!partial || body.redirectUris !== undefined || body.type !== undefined) if (!validateOAuthRedirectUris(effectiveRedirectUris, applicationType).valid) return null;
  if (body.redirectUris !== undefined) data.redirectUris = [...new Set(body.redirectUris as string[])];
  if (body.disabled !== undefined) { if (typeof body.disabled !== 'boolean') return null; data.disabled = body.disabled; }
  return partial && Object.keys(data).length === 0 ? null : data;
}

export function createTenantConsoleRouter(db: PrismaClient, dependencies: TenantConsoleDependencies = {}) {
  const router = new Hono<TenantConsoleContext>();
  router.use('*', (dependencies.sessionMiddleware ?? requireSession) as unknown as MiddlewareHandler<TenantConsoleContext>);
  router.use('/:organizationId/*', async (c, next) => {
    const membership = await db.organizationMembership.findFirst({ where: { ...activeMembershipWhere(c.req.param('organizationId'), new Date()), userId: c.get('user').id }, select: { id: true, organizationId: true, userId: true, role: true } });
    if (!membership) return error(c, 404, 'NOT_FOUND', 'Organization not found');
    c.set('consoleMembership', membership); await next();
  });
  const overview = async (c: Context<TenantConsoleContext>) => {
    const organizationId = c.req.param('organizationId');
    const organization = await db.organization.findUnique({ where: { id: organizationId }, select: { id: true, name: true, plan: true, billingState: true, createdAt: true, updatedAt: true } });
    if (!organization) return error(c, 404, 'NOT_FOUND', 'Organization not found');
    const [entitlements, apps, members] = await Promise.all([resolvePlanEntitlements(db, organizationId), db.oauthClient.count({ where: { organizationId } }), db.organizationMembership.count({ where: activeMembershipWhere(organizationId, new Date()) })]);
    return c.json({ organization: { ...organization, role: c.get('consoleMembership').role }, entitlements: entitlements ? serializeEntitlements(entitlements) : null, usage: { apps, members } });
  };
  router.get('/:organizationId', overview); router.get('/:organizationId/overview', overview);
  router.get('/:organizationId/apps', async (c) => c.json({ apps: await db.oauthClient.findMany({ where: { organizationId: c.req.param('organizationId') }, select: APP_SELECT, orderBy: { createdAt: 'desc' } }) }));
  router.get('/:organizationId/members', async (c) => c.json({ members: (await db.organizationMembership.findMany({ where: activeMembershipWhere(c.req.param('organizationId'), new Date()), select: MEMBER_SELECT, orderBy: { createdAt: 'asc' } })).map(presentMember) }));
  router.post('/:organizationId/members', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
    const body: { address?: unknown } = await c.req.json().catch(() => ({}));
    if (typeof body.address !== 'string') return error(c, 400, 'INVALID_ADDRESS', 'A valid Ethereum address is required');
    let address: `0x${string}`; try { address = getAddress(body.address.trim()); } catch { return error(c, 400, 'INVALID_ADDRESS', 'A valid Ethereum address is required'); }
    const organizationId = c.req.param('organizationId');
    try {
      const result = await db.$transaction(async (tx) => {
        const key = await tx.ethereumKey.findFirst({ where: { address: { equals: address, mode: 'insensitive' }, keyPurpose: 'PERSONAL', archivedAt: null, userId: { not: null } }, select: { userId: true, user: { select: { emailVerified: true } } } });
        if (!key?.userId || !key.user?.emailVerified) return null;
        const existing = await tx.organizationMembership.findFirst({ where: { ...activeMembershipWhere(organizationId, new Date()), userId: key.userId }, select: MEMBER_SELECT });
        if (existing) { if (existing.role !== 'ADMIN') throw new ConsoleMemberAlreadyExistsError(); return { member: presentMember(existing), created: false }; }
        const entitlements = await resolvePlanEntitlements(tx, organizationId); if (!entitlements) return null;
        if (await tx.organizationMembership.count({ where: activeMembershipWhere(organizationId, new Date()) }) >= entitlements.maxOrganizationMembers) throw new ConsoleMemberLimitError();
        const member = await tx.organizationMembership.create({ data: { organizationId, userId: key.userId, role: 'ADMIN' }, select: MEMBER_SELECT });
        return { member: presentMember(member), created: true };
      }, { isolationLevel: 'Serializable' });
      if (!result) return error(c, 404, 'OPENKEY_USER_NOT_FOUND', 'No verified OpenKey account has linked this active personal address');
      return c.json({ member: result.member }, result.created ? 201 : 200);
    } catch (caught) { if (caught instanceof ConsolePlanLimitError) return error(c, 429, 'PLAN_LIMIT_EXCEEDED', 'Organization member limit is exhausted'); if (caught instanceof ConsoleMemberAlreadyExistsError) return error(c, 409, 'MEMBER_ALREADY_EXISTS', 'This OpenKey user is already an organization member'); throw caught; }
  });
  router.delete('/:organizationId/members/:memberId', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
    const organizationId = c.req.param('organizationId'); const now = new Date();
    const result = await db.$transaction(async (tx) => {
      const target = await tx.organizationMembership.findFirst({ where: { id: c.req.param('memberId'), ...activeMembershipWhere(organizationId, now) }, select: { id: true, role: true } });
      if (!target) return 'missing' as const;
      if (target.role === 'ADMIN' && await tx.organizationMembership.count({ where: { ...activeMembershipWhere(organizationId, now), role: 'ADMIN' } }) <= 1) return 'last-admin' as const;
      await tx.organizationMembership.update({ where: { id: target.id }, data: { status: 'REVOKED', revokedAt: now, validUntil: now } });
      return 'removed' as const;
    }, { isolationLevel: 'Serializable' });
    if (result === 'missing') return error(c, 404, 'NOT_FOUND', 'Organization member not found');
    if (result === 'last-admin') return error(c, 409, 'LAST_ADMIN_REQUIRED', 'An organization must retain an active administrator');
    return c.json({ success: true });
  });
  router.post('/:organizationId/apps', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
    const input = parseAppInput(await c.req.json<Record<string, unknown>>().catch(() => ({})));
    if (!input?.name || !input.redirectUris) return error(c, 400, 'INVALID_REQUEST', 'A valid name and redirectUris are required');
    try {
      const client = await db.$transaction(async (tx) => { const organizationId = c.req.param('organizationId'); const entitlements = await resolvePlanEntitlements(tx, organizationId); if (!entitlements) return null; if (await tx.oauthClient.count({ where: { organizationId } }) >= entitlements.maxApps) throw new ConsolePlanLimitError(); return tx.oauthClient.create({ data: { id: randomBytes(16).toString('hex'), clientId: `ok_${randomBytes(16).toString('hex')}`, clientSecret: null, organizationId, userId: c.get('user').id, name: input.name!, uri: input.uri ?? null, icon: input.icon ?? null, redirectUris: input.redirectUris!, scopes: ['openid', 'email', 'keys', 'offline_access'], disabled: false, skipConsent: false, enableEndSession: false, tokenEndpointAuthMethod: 'none', grantTypes: ['authorization_code', 'refresh_token'], responseTypes: ['code'], type: input.type ?? 'spa', public: true, contacts: [] }, select: APP_SELECT }); }, { isolationLevel: 'Serializable' });
      if (!client) return error(c, 404, 'NOT_FOUND', 'Organization not found'); return c.json({ client }, 201);
    } catch (caught) { if (caught instanceof ConsolePlanLimitError) return error(c, 429, 'PLAN_LIMIT_EXCEEDED', 'Application limit is exhausted'); throw caught; }
  });
  router.patch('/:organizationId/apps/:appId', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required'); const where = { id: c.req.param('appId'), organizationId: c.req.param('organizationId') };
    const current = await db.oauthClient.findFirst({ where, select: { type: true, redirectUris: true } }); if (!current) return error(c, 404, 'NOT_FOUND', 'Application not found');
    const data = parseAppInput(await c.req.json<Record<string, unknown>>().catch(() => ({})), true, current); if (!data) return error(c, 400, 'INVALID_REQUEST', 'No valid application changes were supplied');
    await db.oauthClient.updateMany({ where, data }); return c.json({ client: await db.oauthClient.findFirst({ where, select: APP_SELECT }) });
  });
  return router;
}
const prisma = createPrismaClient();
export const tenantConsoleRouter = createTenantConsoleRouter(prisma);
