import { Hono, type Context } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import {
  requireOrganizationCredential,
  type OrganizationContext,
} from '../middleware/organization';
import {
  tenantSafeAccount,
  TenantManagedAccountError,
} from '../services/tenant-managed-accounts';
import { resolvePlanEntitlements, serializeEntitlements } from '../services/plan-entitlements';
import { authorizeKeyOperation, ManagedKeyAuthorizationError } from '../services/managed-key-authorization';
import {
  createWebhookEndpoint,
  LIFECYCLE_EVENTS,
  WebhookEndpointLimitError,
  webhookEndpointLimitForPlan,
  type LifecycleEvent,
} from '../services/lifecycle-webhooks';

const prisma = createPrismaClient();

function deprecatedFlow(c: Context<any, any, any>) {
  c.header('Deprecation', 'true');
  c.header('Sunset', new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toUTCString());
  return c.json({ error: { code: 'REGISTRATION_FLOW_REMOVED', message: 'Registration flow has been removed' } }, 410);
}

export const managedAccountsRouter = new Hono<OrganizationContext>();
managedAccountsRouter.use('*', requireOrganizationCredential);

managedAccountsRouter.post('/managed-account-registration-intents', async (c) => {
  return deprecatedFlow(c);
});

managedAccountsRouter.get('/managed-account-registration-intents/:id', async (c) => {
  return deprecatedFlow(c);
});

managedAccountsRouter.get('/managed-accounts', async (c) => {
  const actor = c.get('organizationActor');
  const externalUserId = c.req.query('externalUserId');
  const rows = await prisma.managedAccount.findMany({
    where: { organizationId: actor.organizationId, ...(externalUserId ? { externalUserId } : {}) },
    select: { id: true },
    orderBy: { createdAt: 'desc' },
    take: 100,
  });
  const accounts = await Promise.all(rows.map((row) => tenantSafeAccount(prisma, actor.organizationId, row.id)));
  return c.json({ accounts });
});

managedAccountsRouter.get('/managed-accounts/:id', async (c) => {
  try {
    return c.json(await tenantSafeAccount(prisma, c.get('organizationActor').organizationId, c.req.param('id')));
  } catch (error) {
    if (error instanceof TenantManagedAccountError) {
      return c.json({ error: { code: 'NOT_FOUND', message: error.message } }, 404);
    }
    throw error;
  }
});

managedAccountsRouter.get('/managed-accounts/:id/tenant-parent-delegation', async (c) => {
  return deprecatedFlow(c);
});

managedAccountsRouter.get('/organization/entitlements', async (c) => {
  const entitlements = await resolvePlanEntitlements(prisma, c.get('organizationActor').organizationId);
  if (!entitlements) return c.json({ error: { code: 'NOT_FOUND', message: 'Organization not found' } }, 404);
  const managedAccounts = await prisma.managedAccount.count({
    where: { organizationId: c.get('organizationActor').organizationId },
  });
  return c.json({
    entitlements: {
      ...serializeEntitlements(entitlements),
      maxWebhookEndpoints: webhookEndpointLimitForPlan(entitlements.plan),
    },
    usage: { managedAccounts },
  });
});

managedAccountsRouter.get('/webhook-endpoints', async (c) => {
  const endpoints = await prisma.webhookEndpoint.findMany({
    where: { organizationId: c.get('organizationActor').organizationId },
    select: { id: true, url: true, eventTypes: true, active: true, createdAt: true, updatedAt: true },
    orderBy: { createdAt: 'desc' },
  });
  return c.json({ endpoints });
});

managedAccountsRouter.post('/webhook-endpoints', async (c) => {
  const actor = c.get('organizationActor');
  const body: { url?: unknown; eventTypes?: unknown } = await c.req.json().catch(() => ({}));
  if (typeof body.url !== 'string' || !Array.isArray(body.eventTypes)
    || body.eventTypes.some((event) => typeof event !== 'string' || !LIFECYCLE_EVENTS.includes(event as LifecycleEvent))) {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'url and valid eventTypes are required' } }, 400);
  }
  const entitlements = await resolvePlanEntitlements(prisma, actor.organizationId);
  if (!entitlements?.webhookDelivery) {
    return c.json({ error: { code: 'PLAN_LIMIT_EXCEEDED', message: 'Webhook delivery is not enabled' } }, 429);
  }
  try {
    const endpoint = await createWebhookEndpoint(prisma, {
      organizationId: actor.organizationId,
      url: body.url,
      eventTypes: body.eventTypes as LifecycleEvent[],
    });
    return c.json(endpoint, 201);
  } catch (error) {
    if (error instanceof WebhookEndpointLimitError) {
      return c.json({ error: { code: 'PLAN_LIMIT_EXCEEDED', message: error.message } }, 429);
    }
    return c.json({ error: { code: 'INVALID_REQUEST', message: error instanceof Error ? error.message : 'Invalid webhook endpoint' } }, 400);
  }
});

managedAccountsRouter.delete('/webhook-endpoints/:id', async (c) => {
  const result = await prisma.webhookEndpoint.updateMany({
    where: { id: c.req.param('id'), organizationId: c.get('organizationActor').organizationId },
    data: { active: false },
  });
  if (result.count === 0) return c.json({ error: { code: 'NOT_FOUND', message: 'Webhook endpoint not found' } }, 404);
  return c.json({ success: true });
});

export const hostedRegistrationRouter = new Hono<SessionContext>();

hostedRegistrationRouter.get('/:token', async (c) => {
  return deprecatedFlow(c);
});

hostedRegistrationRouter.post('/:token/complete', requireSession, async (c) => {
  return deprecatedFlow(c);
});
