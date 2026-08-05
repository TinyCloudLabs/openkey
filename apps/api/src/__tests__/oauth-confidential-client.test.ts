import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash } from 'node:crypto';

process.env.ADMIN_API_KEY = 'admin-test-key';
process.env.OPENKEY_COORDINATIONOS_SUPABASE_CALLBACK_URI =
  'https://coordination.example/auth/v1/callback';

let stored: any = null;
function selected(value: any, select?: Record<string, boolean>) {
  if (!select) return value;
  return Object.fromEntries(Object.keys(select).filter((key) => select[key]).map((key) => [key, value[key]]));
}
const create = mock(async ({ data }: any) => {
  stored = { ...data, createdAt: new Date('2026-07-28T20:00:00.000Z') };
  return stored;
});
const update = mock(async ({ data, select }: any) => {
  stored = { ...stored, ...data };
  return selected(stored, select);
});
const prisma = {
  organization: {
    findUnique: mock(async () => ({
      id: 'organization_1',
      planEntitlements: { maxApps: 10 },
      _count: { oauthClients: 0 },
    })),
  },
  oauthClient: {
    create,
    update,
    findUnique: mock(async ({ select }: any) => stored ? selected(stored, select) : null),
    findFirst: mock(async ({ select }: any) => stored ? selected(stored, select) : null),
    findMany: mock(async ({ select }: any) => stored ? [selected(stored, select)] : []),
  },
};

let router: typeof import('../routes/oauth-admin')['oauthAdminRouter'];
let setDatabase: typeof import('../routes/oauth-admin')['setOauthAdminDatabaseForTests'];
let disconnectDefaultDatabase: typeof import('../routes/oauth-admin')['disconnectOauthAdminDefaultDatabaseForTests'];

beforeAll(async () => {
  ({
    oauthAdminRouter: router,
    setOauthAdminDatabaseForTests: setDatabase,
    disconnectOauthAdminDefaultDatabaseForTests: disconnectDefaultDatabase,
  } = await import('../routes/oauth-admin?coordinationos-confidential-client-isolated' as string));
  setDatabase(prisma as any);
});

afterAll(async () => {
  setDatabase();
  await disconnectDefaultDatabase();
});

beforeEach(() => {
  stored = null;
  create.mockClear();
  update.mockClear();
});

function request(path: string, method: string, body?: unknown) {
  return router.request(path, {
    method,
    headers: {
      authorization: 'Bearer admin-test-key',
      'content-type': 'application/json',
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

const valid = {
  name: 'CoordinationOS',
  type: 'web',
  redirectUris: ['https://coordination.example/auth/v1/callback'],
  scopes: ['openid', 'email', 'keys', 'tinycloud:session'],
};

describe('confidential CoordinationOS OAuth client', () => {
  test('stores only a base64url SHA-256 secret and returns plaintext once', async () => {
    const response = await request('/clients', 'POST', valid);
    expect(response.status).toBe(201);
    const payload = await response.json() as any;
    expect(payload.clientSecret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(stored.clientSecret).toBe(
      createHash('sha256').update(payload.clientSecret, 'utf8').digest('base64url'),
    );
    expect(stored).toMatchObject({
      public: false,
      type: 'web',
      mode: 'PERSONAL',
      tokenEndpointAuthMethod: 'client_secret_basic',
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      scopes: ['openid', 'email', 'keys', 'tinycloud:session'],
    });

    const listed = await request('/clients', 'GET');
    const listedPayload = await listed.json() as any;
    expect(listedPayload.clients[0]).not.toHaveProperty('clientSecret');
    expect(JSON.stringify(listedPayload)).not.toContain(payload.clientSecret);
    const fetched = await request(`/clients/${stored.clientId}`, 'GET');
    const fetchedPayload = await fetched.json() as any;
    expect(fetchedPayload.client).not.toHaveProperty('clientSecret');
    expect(JSON.stringify(fetchedPayload)).not.toContain(payload.clientSecret);
  });

  test.each([
    [{ ...valid, redirectUris: [] }],
    [{ ...valid, redirectUris: [...valid.redirectUris, ...valid.redirectUris] }],
    [{ ...valid, redirectUris: ['https://coordination.example/auth/v1/callback?'] }],
    [{ ...valid, redirectUris: ['https://coordination.example/auth/v1/callback?x=1'] }],
    [{ ...valid, redirectUris: ['https://coordination.example/auth/v1/callback#'] }],
    [{ ...valid, redirectUris: ['https://coordination.example/auth/v1/callback#fragment'] }],
    [{ ...valid, redirectUris: ['https://*.example/auth/v1/callback'] }],
    [{ ...valid, redirectUris: ['https://coordination.example.evil/auth/v1/callback'] }],
    [{ ...valid, redirectUris: ['https://alternate.example/auth/v1/callback'] }],
    [{ ...valid, redirectUris: ['https://@coordination.example/auth/v1/callback'] }],
    [{ ...valid, redirectUris: ['https://user:pass@coordination.example/auth/v1/callback'] }],
    [{ ...valid, redirectUris: ['com.example:/auth/v1/callback'] }],
    [{ ...valid, redirectUris: ['http://coordination.example/auth/v1/callback'] }],
    [{ ...valid, scopes: ['openid', 'email', 'keys'] }],
    [{ ...valid, scopes: [...valid.scopes, 'offline_access'] }],
    [{ ...valid, scopes: [...valid.scopes, 'tinycloud:session'] }],
    [{ ...valid, scopes: 'openid email keys tinycloud:session' }],
    [{ ...valid, type: 'unsupported' }],
  ])('rejects invalid web registration %#', async (body) => {
    const response = await request('/clients', 'POST', body);
    expect(response.status).toBe(400);
    expect(create).not.toHaveBeenCalled();
  });

  test('public SPA/native create responses exactly preserve the baseline shape', async () => {
    for (const type of ['spa', 'native'] as const) {
      stored = null;
      const redirectUris = type === 'native'
        ? ['com.example.app:/oauth/callback']
        : ['https://app.example/callback'];
      const response = await request('/clients', 'POST', {
        name: type,
        type,
        redirectUris,
      });
      expect(response.status).toBe(201);
      const payload = await response.json() as any;
      expect(payload).toEqual({
        success: true,
        client: {
          id: stored.id,
          clientId: stored.clientId,
          name: type,
          redirectUris,
          uri: null,
          type,
          public: true,
          createdAt: '2026-07-28T20:00:00.000Z',
        },
      });
      expect(payload.client).not.toHaveProperty('tokenEndpointAuthMethod');
      expect(payload.client).not.toHaveProperty('grantTypes');
      expect(payload.client).not.toHaveProperty('responseTypes');
      expect(payload.client).not.toHaveProperty('scopes');
      expect(stored.clientSecret).toBeNull();
      expect(stored.public).toBe(true);
      expect(stored.tokenEndpointAuthMethod).toBe('none');
      expect(stored.scopes).not.toContain('tinycloud:session');
    }
  });

  test('tenant-managed, SPA, and native clients never receive TinyCloud signing scopes implicitly', async () => {
    for (const type of ['spa', 'native'] as const) {
      stored = null;
      const redirectUris = type === 'native'
        ? ['com.example.tenant:/oauth/callback']
        : ['https://tenant.example/callback'];
      const response = await request('/organizations/organization_1/clients', 'POST', {
        name: `tenant ${type}`,
        type,
        redirectUris,
      });

      expect(response.status).toBe(201);
      expect(stored).toMatchObject({
        organizationId: 'organization_1',
        mode: 'TENANT_MANAGED',
        type,
        public: true,
        tokenEndpointAuthMethod: 'none',
      });
      expect(stored.scopes).toEqual([
        'openid',
        'email',
        'keys',
        'offline_access',
        'tinycloud:mcp',
      ]);
      expect(stored.scopes).not.toContain('tinycloud:session');
      expect(stored.scopes).not.toContain('tinycloud:manage-key');
    }
  });

  test('web PATCH rejects redirectUris and scopes before update', async () => {
    await request('/clients', 'POST', valid);
    for (const patch of [
      { redirectUris: valid.redirectUris },
      { scopes: valid.scopes },
      { redirectUris: valid.redirectUris, scopes: valid.scopes },
    ]) {
      update.mockClear();
      const response = await request(`/clients/${stored.clientId}`, 'PATCH', patch);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: { code: 'IMMUTABLE_FIELD' } });
      expect(update).not.toHaveBeenCalled();
    }
  });

  test('web create and allowed metadata PATCH retain the sole callback and exact scopes', async () => {
    await request('/clients', 'POST', valid);
    const callback = [...stored.redirectUris];
    const scopes = [...stored.scopes];
    const response = await request(`/clients/${stored.clientId}`, 'PATCH', {
      name: 'CoordinationOS renamed',
      disabled: false,
    });
    expect(response.status).toBe(200);
    expect(stored.redirectUris).toEqual(callback);
    expect(stored.scopes).toEqual(scopes);
    expect(await response.json()).not.toHaveProperty('client.clientSecret');
  });

  test('web registration fails closed when callback configuration is missing or invalid', async () => {
    for (const configured of [undefined, '', 'http://remote.example/auth/v1/callback']) {
      if (configured === undefined) delete process.env.OPENKEY_COORDINATIONOS_SUPABASE_CALLBACK_URI;
      else process.env.OPENKEY_COORDINATIONOS_SUPABASE_CALLBACK_URI = configured;
      create.mockClear();
      const response = await request('/clients', 'POST', valid);
      expect(response.status).toBe(400);
      expect(create).not.toHaveBeenCalled();
    }
    process.env.OPENKEY_COORDINATIONOS_SUPABASE_CALLBACK_URI = valid.redirectUris[0];
  });
});
