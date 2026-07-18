// OAuth Client Administration Routes
// Protected by ADMIN_API_KEY - for registering OAuth clients
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { randomBytes } from 'crypto';
import { issueOrganizationCredential, OrganizationCredentialError } from '../services/organization-credentials';
import { publicPlanDefaults } from '../services/plan-entitlements';
import {
  oauthApplicationType,
  validateOAuthClientMetadataUrl,
  validateOAuthRedirectUris,
} from '../services/oauth-redirect-uris';

const prisma = createPrismaClient();

export const oauthAdminRouter = new Hono();

// Middleware: Require admin API key
oauthAdminRouter.use('*', async (c, next) => {
  const adminKey = process.env.ADMIN_API_KEY;
  if (!adminKey) {
    return c.json({ error: 'Admin API not configured' }, 503);
  }

  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing authorization header' }, 401);
  }

  const providedKey = authHeader.slice(7);
  if (providedKey !== adminKey) {
    return c.json({ error: 'Invalid admin API key' }, 403);
  }

  await next();
});

function generateId(): string {
  return randomBytes(16).toString('hex');
}

function generateClientId(): string {
  return `ok_${randomBytes(16).toString('hex')}`;
}

const publicPlans = ['FREE', 'PRO', 'ENTERPRISE'] as const;

// POST /api/admin/oauth/organizations - demo/admin fixture for tenant creation
oauthAdminRouter.post('/organizations', async (c) => {
  const body = await c.req.json<{
    name: string;
    ownerUserId: string;
    plan?: typeof publicPlans[number];
    brokerDid?: string;
  }>();
  if (!body.name || !body.ownerUserId || (body.plan && !publicPlans.includes(body.plan))) {
    return c.json({ error: 'name, ownerUserId, and a public plan are required' }, 400);
  }
  const plan = body.plan ?? 'FREE';
  const owner = await prisma.user.findUnique({ where: { id: body.ownerUserId }, select: { id: true } });
  if (!owner) return c.json({ error: 'Owner user not found' }, 404);
  const organization = await prisma.$transaction(async (tx) => {
    const created = await tx.organization.create({
      data: { name: body.name, plan, brokerDid: body.brokerDid ?? null },
    });
    await tx.organizationMembership.create({
      data: { organizationId: created.id, userId: body.ownerUserId, role: 'ADMIN' },
    });
    await tx.planEntitlements.create({
      data: { organizationId: created.id, ...publicPlanDefaults(plan) },
    });
    return created;
  });
  return c.json({ organization }, 201);
});

oauthAdminRouter.patch('/organizations/:organizationId/plan', async (c) => {
  const body = await c.req.json<{ plan: typeof publicPlans[number] }>();
  if (!publicPlans.includes(body.plan)) return c.json({ error: 'Unknown public plan' }, 400);
  const defaults = publicPlanDefaults(body.plan);
  try {
    const result = await prisma.$transaction(async (tx) => {
      const organization = await tx.organization.update({
        where: { id: c.req.param('organizationId') },
        data: { plan: body.plan, billingState: body.plan === 'FREE' ? 'FREE' : 'ACTIVE' },
      });
      const entitlements = await tx.planEntitlements.upsert({
        where: { organizationId: organization.id },
        create: { organizationId: organization.id, ...defaults },
        update: defaults,
      });
      return { organization, entitlements };
    });
    return c.json({ ...result, entitlements: { ...result.entitlements, storageBytesPerManagedAccount: result.entitlements.storageBytesPerManagedAccount.toString() } });
  } catch (error: any) {
    if (error.code === 'P2025') return c.json({ error: 'Organization not found' }, 404);
    throw error;
  }
});

oauthAdminRouter.post('/organizations/:organizationId/credentials', async (c) => {
  const body = await c.req.json<{ name: string; subjectUserId: string; kind: 'BROKER' | 'PROVISIONER' }>();
  if (!body.name || !body.subjectUserId || !['BROKER', 'PROVISIONER'].includes(body.kind)) {
    return c.json({ error: 'name, subjectUserId, and kind are required' }, 400);
  }
  const membership = await prisma.organizationMembership.findFirst({
    where: {
      organizationId: c.req.param('organizationId'),
      userId: body.subjectUserId,
      role: 'ADMIN',
      status: 'ACTIVE',
      revokedAt: null,
      validFrom: { lte: new Date() },
      OR: [{ validUntil: null }, { validUntil: { gt: new Date() } }],
    },
    select: { id: true },
  });
  if (!membership) return c.json({ error: 'Active organization administrator not found' }, 404);
  try {
    const issued = await issueOrganizationCredential(prisma, {
      organizationId: c.req.param('organizationId'),
      subjectUserId: body.subjectUserId,
      name: body.name,
      kind: body.kind,
    });
    return c.json(issued, 201);
  } catch (caught) {
    if (caught instanceof OrganizationCredentialError && caught.code === 'ADMIN_REQUIRED') {
      return c.json({ error: 'Active organization administrator not found' }, 404);
    }
    throw caught;
  }
});

oauthAdminRouter.post('/organizations/:organizationId/clients', async (c) => {
  const body = await c.req.json<{ name: string; redirectUris: string[]; uri?: string; icon?: string; type?: 'native' | 'spa' }>();
  if (!body.name || !Array.isArray(body.redirectUris) || body.redirectUris.length === 0) {
    return c.json({ error: 'name and redirectUris are required' }, 400);
  }
  if (body.type !== undefined && body.type !== 'native' && body.type !== 'spa') {
    return c.json({ error: 'type must be native or spa' }, 400);
  }
  const redirectValidation = validateOAuthRedirectUris(body.redirectUris, body.type ?? 'spa');
  if (!redirectValidation.valid) {
    return c.json({ error: redirectValidation.reason }, 400);
  }
  for (const value of [body.uri, body.icon]) {
    if (value !== undefined && value !== '' && !validateOAuthClientMetadataUrl(value).valid) {
      return c.json({ error: 'Application URI and icon must use HTTPS or loopback HTTP' }, 400);
    }
  }
  const organizationId = c.req.param('organizationId');
  const organization = await prisma.organization.findUnique({
    where: { id: organizationId },
    include: { planEntitlements: true, _count: { select: { oauthClients: true } } },
  });
  if (!organization) return c.json({ error: 'Organization not found' }, 404);
  if (!organization.planEntitlements || organization._count.oauthClients >= organization.planEntitlements.maxApps) {
    return c.json({ error: { code: 'PLAN_LIMIT_EXCEEDED', limit: 'maxApps' } }, 429);
  }
  const clientId = generateClientId();
  const client = await prisma.oauthClient.create({
    data: {
      id: generateId(), clientId, clientSecret: null, organizationId, name: body.name,
      uri: body.uri ?? null, icon: body.icon ?? null, redirectUris: body.redirectUris,
      scopes: ['openid', 'email', 'keys', 'offline_access'], disabled: false, skipConsent: false,
      enableEndSession: false, tokenEndpointAuthMethod: 'none', grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'], type: body.type ?? 'spa', public: true, contacts: [],
    },
  });
  return c.json({ client }, 201);
});

// POST /api/admin/oauth/clients - Register a new OAuth client
oauthAdminRouter.post('/clients', async (c) => {
  const body = await c.req.json<{
    name: string;
    redirectUris: string[];
    uri?: string;
    icon?: string;
    type?: 'native' | 'spa';
  }>();

  // Validation
  if (!body.name || typeof body.name !== 'string') {
    return c.json({ error: 'name is required' }, 400);
  }

  if (!Array.isArray(body.redirectUris) || body.redirectUris.length === 0) {
    return c.json({ error: 'redirectUris must be a non-empty array' }, 400);
  }

  const validTypes = ['native', 'spa'];
  if (body.type && !validTypes.includes(body.type)) {
    return c.json({ error: `type must be one of: ${validTypes.join(', ')}` }, 400);
  }
  const redirectValidation = validateOAuthRedirectUris(body.redirectUris, body.type ?? 'spa');
  if (!redirectValidation.valid) {
    return c.json({ error: redirectValidation.reason }, 400);
  }
  for (const value of [body.uri, body.icon]) {
    if (value !== undefined && value !== '' && !validateOAuthClientMetadataUrl(value).valid) {
      return c.json({ error: 'Application URI and icon must use HTTPS or loopback HTTP' }, 400);
    }
  }

  // Generate credentials - all clients are public (PKCE-only)
  const clientId = generateClientId();

  try {
    const client = await prisma.oauthClient.create({
      data: {
        id: generateId(),
        clientId,
        clientSecret: null,
        name: body.name,
        uri: body.uri || null,
        icon: body.icon || null,
        redirectUris: body.redirectUris,
        scopes: ['openid', 'email', 'keys', 'offline_access'],
        disabled: false,
        skipConsent: false,
        enableEndSession: false,
        tokenEndpointAuthMethod: 'none',
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
        type: body.type || 'spa',
        public: true,
        contacts: [],
      },
    });

    return c.json({
      success: true,
      client: {
        id: client.id,
        clientId,
        name: client.name,
        redirectUris: client.redirectUris,
        uri: client.uri,
        type: client.type,
        public: true,
        createdAt: client.createdAt,
      },
    }, 201);
  } catch (error: any) {
    if (error.code === 'P2002') {
      return c.json({ error: 'Client with this ID already exists' }, 409);
    }
    console.error('Failed to create OAuth client:', error);
    return c.json({ error: 'Failed to create client' }, 500);
  }
});

// GET /api/admin/oauth/clients - List all OAuth clients
oauthAdminRouter.get('/clients', async (c) => {
  const clients = await prisma.oauthClient.findMany({
    select: {
      id: true,
      clientId: true,
      name: true,
      uri: true,
      icon: true,
      redirectUris: true,
      type: true,
      disabled: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });

  return c.json({ clients });
});

// GET /api/admin/oauth/clients/:clientId - Get a specific client
oauthAdminRouter.get('/clients/:clientId', async (c) => {
  const clientId = c.req.param('clientId');

  const client = await prisma.oauthClient.findFirst({
    where: { clientId },
    select: {
      id: true,
      clientId: true,
      name: true,
      uri: true,
      icon: true,
      redirectUris: true,
      type: true,
      disabled: true,
      createdAt: true,
    },
  });

  if (!client) {
    return c.json({ error: 'Client not found' }, 404);
  }

  return c.json({ client });
});

// DELETE /api/admin/oauth/clients/:clientId - Delete a client
oauthAdminRouter.delete('/clients/:clientId', async (c) => {
  const clientId = c.req.param('clientId');

  try {
    await prisma.oauthClient.delete({
      where: { clientId },
    });

    return c.json({ success: true });
  } catch (error: any) {
    if (error.code === 'P2025') {
      return c.json({ error: 'Client not found' }, 404);
    }
    console.error('Failed to delete OAuth client:', error);
    return c.json({ error: 'Failed to delete client' }, 500);
  }
});

// PATCH /api/admin/oauth/clients/:clientId - Update a client
oauthAdminRouter.patch('/clients/:clientId', async (c) => {
  const clientId = c.req.param('clientId');
  const body = await c.req.json<{
    name?: string;
    redirectUris?: string[];
    uri?: string;
    icon?: string;
    disabled?: boolean;
    scopes?: string[];
  }>();

  // Validate redirectUris against the persisted client type when provided.
  if (body.redirectUris) {
    const existing = await prisma.oauthClient.findUnique({
      where: { clientId },
      select: { type: true },
    });
    if (!existing) return c.json({ error: 'Client not found' }, 404);
    const redirectValidation = validateOAuthRedirectUris(
      body.redirectUris,
      oauthApplicationType(existing.type),
    );
    if (!redirectValidation.valid) return c.json({ error: redirectValidation.reason }, 400);
  }
  for (const value of [body.uri, body.icon]) {
    if (value !== undefined && value !== '' && !validateOAuthClientMetadataUrl(value).valid) {
      return c.json({ error: 'Application URI and icon must use HTTPS or loopback HTTP' }, 400);
    }
  }

  // Validate scopes if provided
  if (body.scopes) {
    const validScopes = ['openid', 'email', 'keys', 'offline_access'];
    const invalid = body.scopes.filter((s) => !validScopes.includes(s));
    if (invalid.length > 0) {
      return c.json({ error: `Invalid scopes: ${invalid.join(', ')}` }, 400);
    }
  }

  try {
    const client = await prisma.oauthClient.update({
      where: { clientId },
      data: {
        ...(body.name && { name: body.name }),
        ...(body.redirectUris && { redirectUris: body.redirectUris }),
        ...(body.uri !== undefined && { uri: body.uri || null }),
        ...(body.icon !== undefined && { icon: body.icon || null }),
        ...(body.disabled !== undefined && { disabled: body.disabled }),
        ...(body.scopes && { scopes: body.scopes }),
      },
      select: {
        id: true,
        clientId: true,
        name: true,
        uri: true,
        icon: true,
        redirectUris: true,
        type: true,
        disabled: true,
        createdAt: true,
      },
    });

    return c.json({ client });
  } catch (error: any) {
    if (error.code === 'P2025') {
      return c.json({ error: 'Client not found' }, 404);
    }
    console.error('Failed to update OAuth client:', error);
    return c.json({ error: 'Failed to update client' }, 500);
  }
});
