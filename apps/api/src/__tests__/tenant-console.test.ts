import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';

const testPrivateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const now = new Date('2026-07-18T12:00:00.000Z');
const organizations = {
  'org-a': {
    id: 'org-a', name: 'Alpha', plan: 'FREE', billingState: 'FREE', brokerDid: 'did:web:alpha.example',
    createdAt: now, updatedAt: now,
    planEntitlements: {
      id: 'ent-a', organizationId: 'org-a', version: 1, maxApps: 1, maxOrganizationMembers: 3,
      maxManagedAccounts: 100, monthlyActiveManagedUsers: 100, storageBytesPerManagedAccount: 100n,
      requestsPerMinute: 60, maxTenantDelegationTtlSeconds: 3600, maxTenantPolicyVersion: 1,
      webhookDelivery: true, auditRetentionDays: 7, createdAt: now, updatedAt: now,
    },
  },
  'org-b': {
    id: 'org-b', name: 'Beta', plan: 'PRO', billingState: 'ACTIVE', brokerDid: 'did:web:beta.example',
    createdAt: now, updatedAt: now,
    planEntitlements: {
      id: 'ent-b', organizationId: 'org-b', version: 1, maxApps: 10, maxOrganizationMembers: 25,
      maxManagedAccounts: 10_000, monthlyActiveManagedUsers: 10_000, storageBytesPerManagedAccount: 1_000n,
      requestsPerMinute: 600, maxTenantDelegationTtlSeconds: 86_400, maxTenantPolicyVersion: 5,
      webhookDelivery: true, auditRetentionDays: 90, createdAt: now, updatedAt: now,
    },
  },
} as const;

let apps: any[];
let credentials: any[];
let webhooks: any[];

const accountA = {
  id: 'account-a', organizationId: 'org-a', ownerUserId: 'owner-a', keyId: 'private-key-id',
  externalUserId: 'customer-a', state: 'MANAGED', custodyEpoch: 1, policyVersion: 1,
  policyTemplate: 'tinycloud-standard-v1', tenantParentDelegationCid: 'bafy-parent',
  tenantParentDelegation: { private: 'must-not-leak' }, revocationStatus: 'NOT_REQUIRED',
  createdAt: now, updatedAt: now, key: { address: '0x1111111111111111111111111111111111111111' },
};
const accountB = { ...accountA, id: 'account-b', organizationId: 'org-b', externalUserId: 'customer-b' };

const membership = (userId: string, organizationId: string) => {
  const roles: Record<string, Record<string, 'ADMIN' | 'MEMBER'>> = {
    admin: { 'org-a': 'ADMIN' },
    member: { 'org-a': 'MEMBER' },
    'admin-b': { 'org-b': 'ADMIN' },
  };
  const role = roles[userId]?.[organizationId];
  return role ? { id: `${userId}-${organizationId}`, userId, organizationId, role } : null;
};

const prisma = {
  $transaction: mock(async (operation: (tx: any) => unknown) => operation(prisma)),
  organizationMembership: {
    findFirst: mock(async ({ where }: any) => membership(where.userId, where.organizationId)),
    count: mock(async ({ where }: any) => where.organizationId === 'org-a' ? 2 : 1),
  },
  organization: {
    findUnique: mock(async ({ where, select }: any) => {
      const organization = (organizations as any)[where.id];
      if (!organization) return null;
      return Object.fromEntries(Object.keys(select).map((key) => [key, organization[key]]));
    }),
  },
  planEntitlements: {
    create: mock(async () => { throw new Error('unexpected entitlement creation'); }),
  },
  oauthClient: {
    count: mock(async ({ where }: any) => apps.filter((app) => app.organizationId === where.organizationId).length),
    findMany: mock(async ({ where }: any) => apps.filter((app) => app.organizationId === where.organizationId)),
    create: mock(async ({ data }: any) => {
      const app = { ...data, createdAt: now, updatedAt: now };
      apps.push(app);
      return app;
    }),
    updateMany: mock(async ({ where, data }: any) => {
      const app = apps.find((candidate) => candidate.id === where.id && candidate.organizationId === where.organizationId);
      if (!app) return { count: 0 };
      Object.assign(app, data, { updatedAt: now });
      return { count: 1 };
    }),
    findFirst: mock(async ({ where }: any) => apps.find((candidate) =>
      candidate.id === where.id && candidate.organizationId === where.organizationId) ?? null),
  },
  organizationServerCredential: {
    count: mock(async ({ where }: any) => credentials.filter((credential) =>
      credential.organizationId === where.organizationId && !credential.revokedAt).length),
    create: mock(async ({ data }: any) => {
      const credential = { id: `credential-${credentials.length + 1}`, ...data, createdAt: now, lastUsedAt: null, revokedAt: null };
      credentials.push(credential);
      return credential;
    }),
    findMany: mock(async ({ where }: any) => credentials
      .filter((credential) => credential.organizationId === where.organizationId)
      .map(({ secretHash: _secretHash, ...credential }) => credential)),
    updateMany: mock(async ({ where, data }: any) => {
      const credential = credentials.find((candidate) => candidate.id === where.id
        && candidate.organizationId === where.organizationId && !candidate.revokedAt);
      if (!credential) return { count: 0 };
      Object.assign(credential, data);
      return { count: 1 };
    }),
  },
  managedAccount: {
    count: mock(async ({ where }: any) => [accountA, accountB].filter((account) => account.organizationId === where.organizationId).length),
    findFirst: mock(async ({ where }: any) => [accountA, accountB].find((account) =>
      account.id === where.id && account.organizationId === where.organizationId) ?? null),
    findMany: mock(async ({ where }: any) => [accountA, accountB].filter((account) =>
      account.organizationId === where.organizationId
      && (!where.externalUserId || account.externalUserId === where.externalUserId))),
  },
  webhookEndpoint: {
    count: mock(async ({ where }: any) => webhooks.filter((endpoint) =>
      endpoint.organizationId === where.organizationId && endpoint.active).length),
    findMany: mock(async ({ where }: any) => webhooks.filter((endpoint) => endpoint.organizationId === where.organizationId)),
    findFirst: mock(async ({ where }: any) => webhooks.find((endpoint) =>
      endpoint.id === where.id && endpoint.organizationId === where.organizationId) ?? null),
    updateMany: mock(async ({ where, data }: any) => {
      const endpoint = webhooks.find((candidate) => candidate.id === where.id
        && candidate.organizationId === where.organizationId && candidate.active);
      if (!endpoint) return { count: 0 };
      Object.assign(endpoint, data);
      return { count: 1 };
    }),
  },
  webhookDelivery: {
    findMany: mock(async ({ where }: any) => where.organizationId === 'org-a' && where.endpointId === 'webhook-a'
      ? [{ id: 'delivery-a', managedAccountId: 'account-a', eventType: 'managed_account.created', custodyEpoch: 1,
        status: 'DELIVERED', attempts: 1, lastAttemptAt: now, deliveredAt: now, createdAt: now }]
      : []),
  },
};

mock.module('@openkey/db', () => ({
  createPrismaClient: () => prisma,
  Prisma: { JsonNull: null },
}));

mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({ deriveKey: async () => new Uint8Array(32) }),
  generatePrivateKey: () => testPrivateKey,
  getAddressFromPrivateKey: () => privateKeyToAccount(testPrivateKey).address,
  createWalletFromPrivateKey: (privateKey: `0x${string}`) => privateKeyToAccount(privateKey),
  seal: async () => 'sealed',
  unseal: async () => 'secret',
}));

mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    const userId = c.req.header('x-test-user');
    if (!userId) return c.json({ error: 'Unauthorized' }, 401);
    c.set('user', { id: userId, email: `${userId}@example.com` });
    c.set('session', { id: `session-${userId}`, userId, expiresAt: new Date(Date.now() + 60_000) });
    await next();
  }),
}));

async function consoleRouter() {
  const { createTenantConsoleRouter } = await import('../routes/tenant-console');
  return createTenantConsoleRouter(prisma as any, {
    createWebhook: (async (_db: any, input: any) => {
      const endpoint = { id: 'webhook-new', organizationId: input.organizationId, url: input.url,
        eventTypes: input.eventTypes, active: true, createdAt: now, updatedAt: now };
      webhooks.push(endpoint);
      return { endpoint, secret: 'okwhsec_one-time' };
    }) as any,
  });
}

beforeEach(() => {
  apps = [{
    id: 'app-a', clientId: 'ok_app_a', organizationId: 'org-a', name: 'Alpha app', uri: null, icon: null,
    redirectUris: ['https://alpha.example/callback'], type: 'spa', disabled: false, createdAt: now, updatedAt: now,
  }];
  credentials = [];
  webhooks = [{
    id: 'webhook-a', organizationId: 'org-a', url: 'https://alpha.example/webhooks',
    eventTypes: ['managed_account.created'], active: true, createdAt: now, updatedAt: now,
  }];
});

describe('tenant console boundary', () => {
  test('requires a session and permits MEMBER reads but not mutations', async () => {
    const router = await consoleRouter();
    expect((await router.request('/org-a/apps')).status).toBe(401);
    expect((await router.request('/org-a', { headers: { 'x-test-user': 'member' } })).status).toBe(200);
    expect((await router.request('/org-a/apps', { headers: { 'x-test-user': 'member' } })).status).toBe(200);
    expect((await router.request('/org-a/apps', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'member' },
      body: JSON.stringify({ name: 'Nope', redirectUris: ['https://example.com/callback'] }),
    })).status).toBe(403);
  });

  test('hides organizations and resource IDs across tenant boundaries', async () => {
    const router = await consoleRouter();
    expect((await router.request('/org-b/apps', { headers: { 'x-test-user': 'admin' } })).status).toBe(404);
    expect((await router.request('/org-a/apps/app-b', {
      method: 'PATCH', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ disabled: true }),
    })).status).toBe(404);
    expect((await router.request('/org-a/managed-accounts/account-b', {
      headers: { 'x-test-user': 'admin' },
    })).status).toBe(404);
    expect((await router.request('/org-a/webhook-endpoints/webhook-b/deliveries', {
      headers: { 'x-test-user': 'admin' },
    })).status).toBe(404);
  });

  test('returns a credential secret only on creation', async () => {
    const router = await consoleRouter();
    const created = await router.request('/org-a/credentials', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ name: 'Production provisioner', kind: 'PROVISIONER' }),
    });
    expect(created.status).toBe(201);
    const creationBody = await created.json() as any;
    expect(creationBody.secret).toStartWith('oksk_');

    const listed = await router.request('/org-a/credentials', { headers: { 'x-test-user': 'admin' } });
    const listText = await listed.text();
    expect(listText).not.toContain(creationBody.secret);
    expect(listText).not.toContain('secretHash');
  });

  test('enforces the organization application limit', async () => {
    const router = await consoleRouter();
    const response = await router.request('/org-a/apps', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ name: 'Second app', redirectUris: ['https://alpha.example/second'] }),
    });
    expect(response.status).toBe(429);
    expect(await response.json()).toMatchObject({ error: { code: 'PLAN_LIMIT_EXCEEDED' } });

    const created = await router.request('/org-b/apps', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin-b' },
      body: JSON.stringify({ name: 'Beta app', redirectUris: ['https://beta.example/callback'] }),
    });
    expect(created.status).toBe(201);
    expect(await created.json()).toMatchObject({ client: { name: 'Beta app', disabled: false } });

    const loopback = await router.request('/org-b/apps', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin-b' },
      body: JSON.stringify({ name: 'Local SPA', redirectUris: ['http://127.0.0.1:43123/callback'] }),
    });
    expect(loopback.status).toBe(201);

    const native = await router.request('/org-b/apps', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin-b' },
      body: JSON.stringify({
        name: 'Native app', type: 'native', redirectUris: ['com.example.product:/oauth/callback'],
      }),
    });
    expect(native.status).toBe(201);
  });

  test('rejects executable redirect and metadata URLs on create and patch', async () => {
    const router = await consoleRouter();
    for (const redirectUri of ['javascript:alert(1)', 'data:text/html,owned', 'file:///tmp/callback']) {
      const response = await router.request('/org-b/apps', {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin-b' },
        body: JSON.stringify({ name: 'Unsafe app', redirectUris: [redirectUri] }),
      });
      expect(response.status).toBe(400);
    }
    const patch = await router.request('/org-a/apps/app-a', {
      method: 'PATCH', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ redirectUris: ['javascript:alert(1)'] }),
    });
    expect(patch.status).toBe(400);
    const metadata = await router.request('/org-a/apps/app-a', {
      method: 'PATCH', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ uri: 'data:text/html,owned' }),
    });
    expect(metadata.status).toBe(400);
  });

  test('minimizes managed-account fields and paginates list responses', async () => {
    const router = await consoleRouter();
    const response = await router.request('/org-a/managed-accounts/account-a', {
      headers: { 'x-test-user': 'member' },
    });
    expect(response.status).toBe(200);
    const body = await response.json() as any;
    expect(body.account).toMatchObject({ managedAccountId: 'account-a', externalUserId: 'customer-a' });
    expect(body.account).not.toHaveProperty('ownerUserId');
    expect(body.account).not.toHaveProperty('keyId');
    expect(body.account).not.toHaveProperty('tenantParentDelegation');

    const page = await router.request('/org-a/managed-accounts?limit=1', {
      headers: { 'x-test-user': 'member' },
    });
    expect(page.status).toBe(200);
    expect((await page.json() as any).accounts).toHaveLength(1);
  });

  test('creates webhook secrets once and scopes delivery history to the endpoint tenant', async () => {
    const router = await consoleRouter();
    const created = await router.request('/org-a/webhook-endpoints', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ url: 'https://alpha.example/new-hook', eventTypes: ['managed_account.created'] }),
    });
    expect(created.status).toBe(201);
    expect(await created.json()).toMatchObject({ secret: 'okwhsec_one-time' });

    const deliveries = await router.request('/org-a/webhook-endpoints/webhook-a/deliveries', {
      headers: { 'x-test-user': 'member' },
    });
    expect(deliveries.status).toBe(200);
    expect((await deliveries.json() as any).deliveries).toHaveLength(1);
  });
});

describe('registration policy catalog', () => {
  test('rejects unsupported template labels and versions before persistence', async () => {
    const { createRegistrationIntent } = await import('../services/registration-intents');
    const actor = { credentialId: 'credential', organizationId: 'org-a', subjectUserId: 'admin', kind: 'PROVISIONER' } as const;
    const input = { clientId: 'ok_app_a', externalUserId: 'customer', redirectUri: 'https://alpha.example/callback' };
    await expect(createRegistrationIntent(prisma as any, actor, 'unsupported-template', {
      ...input, policyTemplate: 'custom-but-hardcoded', policyVersion: 1,
    })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(createRegistrationIntent(prisma as any, actor, 'unsupported-version', {
      ...input, policyTemplate: 'tinycloud-standard-v1', policyVersion: 2,
    })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });
});
