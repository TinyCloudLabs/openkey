import { randomBytes } from 'node:crypto';
import { Hono, type Context, type MiddlewareHandler } from 'hono';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import { issueOrganizationCredential, OrganizationCredentialError } from '../services/organization-credentials';
import { resolvePlanEntitlements, serializeEntitlements } from '../services/plan-entitlements';
import {
  createWebhookEndpoint,
  LIFECYCLE_EVENTS,
  WebhookEndpointLimitError,
  webhookEndpointLimitForPlan,
  type LifecycleEvent,
} from '../services/lifecycle-webhooks';
import { RegistrationIntentError, tenantSafeAccount } from '../services/registration-intents';
import {
  oauthApplicationType,
  validateOAuthClientMetadataUrl,
  validateOAuthRedirectUris,
  type OAuthApplicationType,
} from '../services/oauth-redirect-uris';

type ConsoleMembership = {
  id: string;
  organizationId: string;
  userId: string;
  role: 'ADMIN' | 'MEMBER';
};

type TenantConsoleContext = SessionContext & {
  Variables: SessionContext['Variables'] & {
    consoleMembership: ConsoleMembership;
  };
};

type TenantConsoleDependencies = {
  sessionMiddleware?: MiddlewareHandler<SessionContext>;
  issueCredential?: typeof issueOrganizationCredential;
  createWebhook?: typeof createWebhookEndpoint;
};

class ConsolePlanLimitError extends Error {}

const APP_SELECT = {
  id: true,
  clientId: true,
  name: true,
  uri: true,
  icon: true,
  redirectUris: true,
  type: true,
  disabled: true,
  createdAt: true,
  updatedAt: true,
} as const;

const CREDENTIAL_SELECT = {
  id: true,
  name: true,
  kind: true,
  secretPrefix: true,
  subjectUserId: true,
  createdAt: true,
  lastUsedAt: true,
  revokedAt: true,
} as const;

function error(c: Context, status: 400 | 403 | 404 | 429, code: string, message: string) {
  return c.json({ error: { code, message } }, status);
}

function isAdmin(c: Context<TenantConsoleContext>): boolean {
  return c.get('consoleMembership').role === 'ADMIN';
}

function parseLimit(value: string | undefined): number | null {
  if (value === undefined) return 50;
  if (!/^\d+$/.test(value)) return null;
  const limit = Number(value);
  return limit >= 1 && limit <= 100 ? limit : null;
}

function parseAppInput(
  body: Record<string, unknown>,
  partial = false,
  current?: { type: string | null; redirectUris: string[] },
) {
  const data: {
    name?: string;
    redirectUris?: string[];
    uri?: string | null;
    icon?: string | null;
    type?: 'native' | 'spa';
    disabled?: boolean;
  } = {};
  if (!partial || body.name !== undefined) {
    if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 100) return null;
    data.name = body.name.trim();
  }
  let applicationType: OAuthApplicationType = current
    ? oauthApplicationType(current.type)
    : 'spa';
  if (body.uri !== undefined) {
    if (body.uri !== null && body.uri !== '' && !validateOAuthClientMetadataUrl(body.uri).valid) return null;
    data.uri = body.uri ? body.uri as string : null;
  }
  if (body.icon !== undefined) {
    if (body.icon !== null && body.icon !== '' && !validateOAuthClientMetadataUrl(body.icon).valid) return null;
    data.icon = body.icon ? body.icon as string : null;
  }
  if (body.type !== undefined) {
    if (body.type !== 'native' && body.type !== 'spa') return null;
    data.type = body.type;
    applicationType = body.type;
  }
  const effectiveRedirectUris = body.redirectUris ?? current?.redirectUris;
  if (!partial || body.redirectUris !== undefined || body.type !== undefined) {
    if (!validateOAuthRedirectUris(effectiveRedirectUris, applicationType).valid) return null;
  }
  if (body.redirectUris !== undefined) {
    data.redirectUris = [...new Set(body.redirectUris as string[])];
  }
  if (body.disabled !== undefined) {
    if (typeof body.disabled !== 'boolean') return null;
    data.disabled = body.disabled;
  }
  if (partial && Object.keys(data).length === 0) return null;
  return data;
}

function presentAccount(account: {
  id: string;
  externalUserId: string;
  state: string;
  custodyEpoch: number;
  policyVersion: number;
  policyTemplate: string;
  tenantParentDelegationCid: string | null;
  revocationStatus: string;
  createdAt: Date;
  updatedAt: Date;
  key: { address: string };
}) {
  return {
    managedAccountId: account.id,
    externalUserId: account.externalUserId,
    address: account.key.address,
    ownerDid: `did:pkh:eip155:1:${account.key.address}`,
    state: account.state,
    custodyEpoch: account.custodyEpoch,
    policyTemplate: account.policyTemplate,
    policyVersion: account.policyVersion,
    tenantParentDelegationCid: account.tenantParentDelegationCid,
    tenantAccess: account.revocationStatus,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}

export function createTenantConsoleRouter(
  db: PrismaClient,
  dependencies: TenantConsoleDependencies = {},
) {
  const router = new Hono<TenantConsoleContext>();
  const sessionMiddleware = dependencies.sessionMiddleware ?? requireSession;
  const issueCredential = dependencies.issueCredential ?? issueOrganizationCredential;
  const createWebhook = dependencies.createWebhook ?? createWebhookEndpoint;

  router.use('*', sessionMiddleware as unknown as MiddlewareHandler<TenantConsoleContext>);
  router.use('/:organizationId/*', async (c, next) => {
    const now = new Date();
    const membership = await db.organizationMembership.findFirst({
      where: {
        organizationId: c.req.param('organizationId'),
        userId: c.get('user').id,
        status: 'ACTIVE',
        revokedAt: null,
        validFrom: { lte: now },
        OR: [{ validUntil: null }, { validUntil: { gt: now } }],
      },
      select: { id: true, organizationId: true, userId: true, role: true },
    });
    if (!membership) return error(c, 404, 'NOT_FOUND', 'Organization not found');
    c.set('consoleMembership', membership);
    await next();
  });

  const organizationOverview = async (c: Context<TenantConsoleContext>) => {
    const organizationId = c.req.param('organizationId');
    const organization = await db.organization.findUnique({
      where: { id: organizationId },
      select: {
        id: true,
        name: true,
        plan: true,
        billingState: true,
        brokerDid: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    if (!organization) return error(c, 404, 'NOT_FOUND', 'Organization not found');
    const [entitlements, apps, managedAccounts, members, credentials, webhookEndpoints] = await Promise.all([
      resolvePlanEntitlements(db, organizationId),
      db.oauthClient.count({ where: { organizationId } }),
      db.managedAccount.count({ where: { organizationId } }),
      db.organizationMembership.count({
        where: { organizationId, status: 'ACTIVE', revokedAt: null },
      }),
      db.organizationServerCredential.count({ where: { organizationId, revokedAt: null } }),
      db.webhookEndpoint.count({ where: { organizationId, active: true } }),
    ]);
    return c.json({
      organization: { ...organization, role: c.get('consoleMembership').role },
      entitlements: entitlements ? {
        ...serializeEntitlements(entitlements),
        maxWebhookEndpoints: webhookEndpointLimitForPlan(entitlements.plan),
      } : null,
      usage: { apps, managedAccounts, members, credentials, webhookEndpoints },
    });
  };

  router.get('/:organizationId', organizationOverview);
  router.get('/:organizationId/overview', organizationOverview);

  router.get('/:organizationId/apps', async (c) => {
    const apps = await db.oauthClient.findMany({
      where: { organizationId: c.req.param('organizationId') },
      select: APP_SELECT,
      orderBy: { createdAt: 'desc' },
    });
    return c.json({ apps });
  });

  router.post('/:organizationId/apps', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
    const body: Record<string, unknown> = await c.req.json<Record<string, unknown>>().catch(() => ({}));
    const input = parseAppInput(body);
    if (!input?.name || !input.redirectUris) {
      return error(c, 400, 'INVALID_REQUEST', 'A valid name and redirectUris are required');
    }
    const name = input.name;
    const redirectUris = input.redirectUris;
    const organizationId = c.req.param('organizationId');
    try {
      let client;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          client = await db.$transaction(async (tx) => {
            const entitlements = await resolvePlanEntitlements(tx, organizationId);
            if (!entitlements) return null;
            const currentApps = await tx.oauthClient.count({ where: { organizationId } });
            if (currentApps >= entitlements.maxApps) throw new ConsolePlanLimitError();
            return tx.oauthClient.create({
              data: {
                id: randomBytes(16).toString('hex'),
                clientId: `ok_${randomBytes(16).toString('hex')}`,
                clientSecret: null,
                organizationId,
                userId: c.get('user').id,
                name,
                uri: input.uri ?? null,
                icon: input.icon ?? null,
                redirectUris,
                scopes: ['openid', 'email', 'keys', 'offline_access'],
                disabled: false,
                skipConsent: false,
                enableEndSession: false,
                tokenEndpointAuthMethod: 'none',
                grantTypes: ['authorization_code', 'refresh_token'],
                responseTypes: ['code'],
                type: input.type ?? 'spa',
                public: true,
                contacts: [],
              },
              select: APP_SELECT,
            });
          }, { isolationLevel: 'Serializable' });
          break;
        } catch (caught) {
          if ((caught as { code?: string }).code === 'P2034' && attempt < 2) continue;
          throw caught;
        }
      }
      if (!client) return error(c, 404, 'NOT_FOUND', 'Organization not found');
      return c.json({ client }, 201);
    } catch (caught) {
      if (caught instanceof ConsolePlanLimitError) {
        return error(c, 429, 'PLAN_LIMIT_EXCEEDED', 'Application limit is exhausted');
      }
      throw caught;
    }
  });

  router.patch('/:organizationId/apps/:appId', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
    const body: Record<string, unknown> = await c.req.json<Record<string, unknown>>().catch(() => ({}));
    const where = { id: c.req.param('appId'), organizationId: c.req.param('organizationId') };
    const current = await db.oauthClient.findFirst({
      where,
      select: { id: true, type: true, redirectUris: true },
    });
    if (!current) return error(c, 404, 'NOT_FOUND', 'Application not found');
    const data = parseAppInput(body, true, current);
    if (!data) return error(c, 400, 'INVALID_REQUEST', 'No valid application changes were supplied');
    const result = await db.oauthClient.updateMany({ where, data });
    if (result.count === 0) return error(c, 404, 'NOT_FOUND', 'Application not found');
    const client = await db.oauthClient.findFirst({ where, select: APP_SELECT });
    return c.json({ client });
  });

  router.get('/:organizationId/credentials', async (c) => {
    const credentials = await db.organizationServerCredential.findMany({
      where: { organizationId: c.req.param('organizationId') },
      select: CREDENTIAL_SELECT,
      orderBy: { createdAt: 'desc' },
    });
    return c.json({ credentials });
  });

  router.post('/:organizationId/credentials', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
    const body: Record<string, unknown> = await c.req.json<Record<string, unknown>>().catch(() => ({}));
    if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 100
      || (body.kind !== 'BROKER' && body.kind !== 'PROVISIONER')) {
      return error(c, 400, 'INVALID_REQUEST', 'A valid name and credential kind are required');
    }
    try {
      const issued = await issueCredential(db, {
        organizationId: c.req.param('organizationId'),
        subjectUserId: c.get('user').id,
        name: body.name.trim(),
        kind: body.kind,
      });
      return c.json(issued, 201);
    } catch (caught) {
      if (caught instanceof OrganizationCredentialError && caught.code === 'ADMIN_REQUIRED') {
        return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
      }
      throw caught;
    }
  });

  router.delete('/:organizationId/credentials/:credentialId', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
    const result = await db.organizationServerCredential.updateMany({
      where: {
        id: c.req.param('credentialId'),
        organizationId: c.req.param('organizationId'),
        revokedAt: null,
      },
      data: { revokedAt: new Date() },
    });
    if (result.count === 0) return error(c, 404, 'NOT_FOUND', 'Credential not found');
    return c.json({ success: true });
  });

  router.get('/:organizationId/managed-accounts', async (c) => {
    const limit = parseLimit(c.req.query('limit'));
    if (!limit) return error(c, 400, 'INVALID_REQUEST', 'limit must be between 1 and 100');
    const organizationId = c.req.param('organizationId');
    const cursor = c.req.query('cursor');
    if (cursor) {
      const cursorAccount = await db.managedAccount.findFirst({
        where: { id: cursor, organizationId },
        select: { id: true },
      });
      if (!cursorAccount) return error(c, 404, 'NOT_FOUND', 'Managed account not found');
    }
    const externalUserId = c.req.query('externalUserId');
    const accounts = await db.managedAccount.findMany({
      where: { organizationId, ...(externalUserId ? { externalUserId } : {}) },
      select: {
        id: true,
        externalUserId: true,
        state: true,
        custodyEpoch: true,
        policyVersion: true,
        policyTemplate: true,
        tenantParentDelegationCid: true,
        revocationStatus: true,
        createdAt: true,
        updatedAt: true,
        key: { select: { address: true } },
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    const hasMore = accounts.length > limit;
    const page = accounts.slice(0, limit);
    return c.json({
      accounts: page.map(presentAccount),
      nextCursor: hasMore ? page.at(-1)?.id ?? null : null,
    });
  });

  router.get('/:organizationId/managed-accounts/:accountId', async (c) => {
    try {
      return c.json({ account: await tenantSafeAccount(
        db,
        c.req.param('organizationId'),
        c.req.param('accountId'),
      ) });
    } catch (caught) {
      if (caught instanceof RegistrationIntentError && caught.code === 'INTENT_NOT_FOUND') {
        return error(c, 404, 'NOT_FOUND', 'Managed account not found');
      }
      throw caught;
    }
  });

  router.get('/:organizationId/webhook-endpoints', async (c) => {
    const endpoints = await db.webhookEndpoint.findMany({
      where: { organizationId: c.req.param('organizationId') },
      select: { id: true, url: true, eventTypes: true, active: true, createdAt: true, updatedAt: true },
      orderBy: { createdAt: 'desc' },
    });
    return c.json({ endpoints, supportedEventTypes: LIFECYCLE_EVENTS });
  });

  router.post('/:organizationId/webhook-endpoints', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
    const body: Record<string, unknown> = await c.req.json<Record<string, unknown>>().catch(() => ({}));
    if (typeof body.url !== 'string' || !Array.isArray(body.eventTypes)
      || body.eventTypes.length === 0
      || body.eventTypes.some((event) => typeof event !== 'string'
        || !LIFECYCLE_EVENTS.includes(event as LifecycleEvent))) {
      return error(c, 400, 'INVALID_REQUEST', 'A valid URL and eventTypes are required');
    }
    const organizationId = c.req.param('organizationId');
    const entitlements = await resolvePlanEntitlements(db, organizationId);
    if (!entitlements?.webhookDelivery) {
      return error(c, 429, 'PLAN_LIMIT_EXCEEDED', 'Webhook delivery is not enabled');
    }
    try {
      const endpoint = await createWebhook(db, {
        organizationId,
        url: body.url,
        eventTypes: body.eventTypes as LifecycleEvent[],
      });
      return c.json(endpoint, 201);
    } catch (caught) {
      if (caught instanceof WebhookEndpointLimitError) {
        return error(c, 429, 'PLAN_LIMIT_EXCEEDED', caught.message);
      }
      return error(c, 400, 'INVALID_REQUEST', caught instanceof Error ? caught.message : 'Invalid webhook endpoint');
    }
  });

  router.delete('/:organizationId/webhook-endpoints/:endpointId', async (c) => {
    if (!isAdmin(c)) return error(c, 403, 'FORBIDDEN', 'Administrator access is required');
    const result = await db.webhookEndpoint.updateMany({
      where: {
        id: c.req.param('endpointId'),
        organizationId: c.req.param('organizationId'),
        active: true,
      },
      data: { active: false },
    });
    if (result.count === 0) return error(c, 404, 'NOT_FOUND', 'Webhook endpoint not found');
    return c.json({ success: true });
  });

  router.get('/:organizationId/webhook-endpoints/:endpointId/deliveries', async (c) => {
    const limit = parseLimit(c.req.query('limit'));
    if (!limit) return error(c, 400, 'INVALID_REQUEST', 'limit must be between 1 and 100');
    const organizationId = c.req.param('organizationId');
    const endpointId = c.req.param('endpointId');
    const endpoint = await db.webhookEndpoint.findFirst({
      where: { id: endpointId, organizationId },
      select: { id: true },
    });
    if (!endpoint) return error(c, 404, 'NOT_FOUND', 'Webhook endpoint not found');
    const deliveries = await db.webhookDelivery.findMany({
      where: { organizationId, endpointId },
      select: {
        id: true,
        managedAccountId: true,
        eventType: true,
        custodyEpoch: true,
        status: true,
        attempts: true,
        lastAttemptAt: true,
        deliveredAt: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    return c.json({ deliveries });
  });

  return router;
}

const prisma = createPrismaClient();
export const tenantConsoleRouter = createTenantConsoleRouter(prisma);
