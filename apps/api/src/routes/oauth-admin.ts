// OAuth Client Administration Routes
// Protected by ADMIN_API_KEY - for registering OAuth clients
import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import { createHash, randomBytes } from 'crypto';

const prisma = new PrismaClient();

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

function generateClientSecret(): string {
  return `oks_${randomBytes(32).toString('hex')}`;
}

function hashSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex');
}

// POST /api/admin/oauth/clients - Register a new OAuth client
oauthAdminRouter.post('/clients', async (c) => {
  const body = await c.req.json<{
    name: string;
    redirectUris: string[];
    uri?: string;
    icon?: string;
    type?: 'web' | 'native' | 'spa';
  }>();

  // Validation
  if (!body.name || typeof body.name !== 'string') {
    return c.json({ error: 'name is required' }, 400);
  }

  if (!Array.isArray(body.redirectUris) || body.redirectUris.length === 0) {
    return c.json({ error: 'redirectUris must be a non-empty array' }, 400);
  }

  for (const uri of body.redirectUris) {
    try {
      new URL(uri);
    } catch {
      return c.json({ error: `Invalid redirect URI: ${uri}` }, 400);
    }
  }

  const validTypes = ['web', 'native', 'spa'];
  if (body.type && !validTypes.includes(body.type)) {
    return c.json({ error: `type must be one of: ${validTypes.join(', ')}` }, 400);
  }

  // Generate credentials
  const clientId = generateClientId();
  const isPublic = body.type === 'spa' || body.type === 'native';
  const clientSecret = isPublic ? null : generateClientSecret();
  const hashedSecret = clientSecret ? hashSecret(clientSecret) : null;

  try {
    const client = await prisma.oauthClient.create({
      data: {
        id: generateId(),
        clientId,
        clientSecret: hashedSecret,
        name: body.name,
        uri: body.uri || null,
        icon: body.icon || null,
        redirectUris: body.redirectUris,
        scopes: ['openid'],
        disabled: false,
        skipConsent: false,
        enableEndSession: false,
        tokenEndpointAuthMethod: isPublic ? 'none' : 'client_secret_basic',
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
        type: body.type || 'web',
        public: isPublic,
        contacts: [],
      },
    });

    return c.json({
      success: true,
      client: {
        id: client.id,
        clientId,
        clientSecret: clientSecret || undefined, // Only returned on creation, not for public clients
        name: client.name,
        redirectUris: client.redirectUris,
        uri: client.uri,
        type: client.type,
        public: isPublic,
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
  }>();

  // Validate redirectUris if provided
  if (body.redirectUris) {
    if (!Array.isArray(body.redirectUris) || body.redirectUris.length === 0) {
      return c.json({ error: 'redirectUris must be a non-empty array' }, 400);
    }
    for (const uri of body.redirectUris) {
      try {
        new URL(uri);
      } catch {
        return c.json({ error: `Invalid redirect URI: ${uri}` }, 400);
      }
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
