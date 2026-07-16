import { Hono, type Context } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import {
  requireOrganizationCredential,
  type OrganizationContext,
} from '../middleware/organization';
import {
  completeRegistrationIntent,
  createRegistrationIntent,
  RegistrationIntentError,
  resolveRegistrationIntent,
  tenantSafeAccount,
} from '../services/registration-intents';
import { resolvePlanEntitlements, serializeEntitlements } from '../services/plan-entitlements';
import { authorizeKeyOperation, ManagedKeyAuthorizationError } from '../services/managed-key-authorization';
import { createWebhookEndpoint, LIFECYCLE_EVENTS, type LifecycleEvent } from '../services/lifecycle-webhooks';

const prisma = createPrismaClient();

function registrationError(c: Context<any, any, any>, error: RegistrationIntentError) {
  const statuses = {
    INVALID_REQUEST: 400,
    CLIENT_NOT_FOUND: 404,
    REDIRECT_URI_MISMATCH: 400,
    IDEMPOTENCY_CONFLICT: 409,
    INTENT_NOT_FOUND: 404,
    INTENT_EXPIRED: 410,
    INTENT_NOT_PENDING: 409,
    OWNER_PASSKEY_REQUIRED: 409,
    PROVISIONING_NOT_ALLOWED: 403,
    PLAN_LIMIT_EXCEEDED: 429,
  } as const;
  return c.json({ error: { code: error.code, message: error.message } }, statuses[error.code]);
}

export const managedAccountsRouter = new Hono<OrganizationContext>();
managedAccountsRouter.use('*', requireOrganizationCredential);

managedAccountsRouter.post('/managed-account-registration-intents', async (c) => {
  const idempotencyKey = c.req.header('Idempotency-Key');
  if (!idempotencyKey || idempotencyKey.length > 200) {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'Idempotency-Key is required' } }, 400);
  }
  const body = await c.req.json<Record<string, unknown>>().catch(() => null);
  if (!body
    || typeof body.clientId !== 'string'
    || typeof body.externalUserId !== 'string'
    || typeof body.redirectUri !== 'string'
    || typeof body.policyTemplate !== 'string'
    || body.externalUserId.length === 0
    || body.externalUserId.length > 255
    || body.policyTemplate.length === 0
    || (body.policyVersion !== undefined && (!Number.isSafeInteger(body.policyVersion) || Number(body.policyVersion) < 1))
    || (body.metadata !== undefined && (!body.metadata || typeof body.metadata !== 'object' || Array.isArray(body.metadata)))) {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'Invalid registration intent request' } }, 400);
  }
  try {
    const result = await createRegistrationIntent(
      prisma,
      c.get('organizationActor'),
      idempotencyKey,
      {
        clientId: body.clientId,
        externalUserId: body.externalUserId,
        redirectUri: body.redirectUri,
        policyTemplate: body.policyTemplate,
        ...(body.policyVersion === undefined ? {} : { policyVersion: Number(body.policyVersion) }),
        ...(body.metadata === undefined ? {} : { metadata: body.metadata as Record<string, unknown> }),
      },
    );
    return c.json(result, 201);
  } catch (error) {
    if (error instanceof RegistrationIntentError) return registrationError(c, error);
    throw error;
  }
});

managedAccountsRouter.get('/managed-account-registration-intents/:id', async (c) => {
  const actor = c.get('organizationActor');
  const intent = await prisma.registrationIntent.findFirst({
    where: { id: c.req.param('id'), organizationId: actor.organizationId },
    select: { id: true, status: true, expiresAt: true, managedAccountId: true, consumedAt: true },
  });
  if (!intent) return c.json({ error: { code: 'NOT_FOUND', message: 'Registration intent not found' } }, 404);
  return c.json(intent);
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
    if (error instanceof RegistrationIntentError) return registrationError(c, error);
    throw error;
  }
});

managedAccountsRouter.get('/managed-accounts/:id/tenant-parent-delegation', async (c) => {
  const actor = c.get('organizationActor');
  if (actor.kind !== 'BROKER') {
    return c.json({ error: { code: 'OPERATION_NOT_ALLOWED', message: 'A broker credential is required' } }, 403);
  }
  const expectedEpoch = Number(c.req.query('expectedEpoch'));
  const account = await prisma.managedAccount.findFirst({
    where: { id: c.req.param('id'), organizationId: actor.organizationId },
    select: { id: true, keyId: true, tenantParentDelegationCid: true, tenantParentDelegation: true, tenantParentExpiresAt: true },
  });
  if (!account) return c.json({ error: { code: 'NOT_FOUND', message: 'Managed account not found' } }, 404);
  try {
    await authorizeKeyOperation(prisma, {
      type: 'organization', credentialId: actor.credentialId, managedAccountId: account.id,
      keyId: account.keyId, expectedEpoch, request: { operation: 'READ_MANAGED_ACCOUNT' },
    });
    if (!account.tenantParentDelegationCid || !account.tenantParentDelegation) {
      return c.json({ error: { code: 'PARENT_UNAVAILABLE', message: 'Tenant parent delegation is unavailable' } }, 409);
    }
    return c.json({
      delegationCid: account.tenantParentDelegationCid,
      delegation: account.tenantParentDelegation,
      expiresAt: account.tenantParentExpiresAt,
      custodyEpoch: expectedEpoch,
    });
  } catch (error) {
    if (error instanceof ManagedKeyAuthorizationError) {
      return c.json({ error: { code: error.code, message: error.message } }, error.code === 'MANAGED_ACCOUNT_NOT_FOUND' ? 404 : 409);
    }
    throw error;
  }
});

managedAccountsRouter.get('/organization/entitlements', async (c) => {
  const entitlements = await resolvePlanEntitlements(prisma, c.get('organizationActor').organizationId);
  if (!entitlements) return c.json({ error: { code: 'NOT_FOUND', message: 'Organization not found' } }, 404);
  const managedAccounts = await prisma.managedAccount.count({
    where: { organizationId: c.get('organizationActor').organizationId },
  });
  return c.json({ entitlements: serializeEntitlements(entitlements), usage: { managedAccounts } });
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
  try {
    const intent = await resolveRegistrationIntent(prisma, c.req.param('token'));
    return c.json({
      intent: {
        organization: intent.organization,
        clientId: intent.publicClientId,
        redirectUri: intent.redirectUri,
        policyTemplate: intent.policyTemplate,
        policyVersion: intent.policyVersion,
        metadata: intent.metadata,
        status: intent.status,
        expiresAt: intent.expiresAt,
      },
    });
  } catch (error) {
    if (error instanceof RegistrationIntentError) return registrationError(c, error);
    throw error;
  }
});

hostedRegistrationRouter.post('/:token/complete', requireSession, async (c) => {
  try {
    const account = await completeRegistrationIntent(prisma, c.req.param('token'), c.get('user').id);
    return c.json({ account });
  } catch (error) {
    if (error instanceof RegistrationIntentError) return registrationError(c, error);
    throw error;
  }
});
