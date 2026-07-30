import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';

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
let organizationMemberships: any[];

const users = {
  admin: {
    id: 'admin', email: 'admin@example.com', name: 'Alpha owner', emailVerified: true,
    ethereumKeys: [{ address: '0x1111111111111111111111111111111111111111' }],
  },
  member: {
    id: 'member', email: 'member@example.com', name: 'Alpha member', emailVerified: true,
    ethereumKeys: [{ address: '0x2222222222222222222222222222222222222222' }],
  },
  'admin-b': {
    id: 'admin-b', email: 'admin-b@example.com', name: 'Beta owner', emailVerified: true,
    ethereumKeys: [{ address: '0x3333333333333333333333333333333333333333' }],
  },
  target: {
    id: 'target', email: 'target@example.com', name: 'Target admin', emailVerified: true,
    ethereumKeys: [{ address: '0xd559CCd9EB87c530A9a349262669386dE93cf412' }],
  },
  secondTarget: {
    id: 'second-target', email: 'second@example.com', name: 'Second target', emailVerified: true,
    ethereumKeys: [{ address: '0x4444444444444444444444444444444444444444' }],
  },
} as const;

const accountA = {
  id: 'account-a', organizationId: 'org-a', ownerUserId: 'owner-a', keyId: 'private-key-id',
  subjectEmail: 'customer-a@example.com',
  externalUserId: 'customer-a', state: 'MANAGED', custodyEpoch: 1, policyVersion: 1,
  policyTemplate: 'tinycloud-standard-v1', tenantParentDelegationCid: 'bafy-parent',
  tenantParentDelegation: { private: 'must-not-leak' }, revocationStatus: 'NOT_REQUIRED',
  createdAt: now, updatedAt: now, key: { address: '0x1111111111111111111111111111111111111111' },
};
const accountB = { ...accountA, id: 'account-b', organizationId: 'org-b', externalUserId: 'customer-b' };

const prisma = {
  $transaction: mock(async (operation: (tx: any) => unknown) => operation(prisma)),
  organizationMembership: {
    findFirst: mock(async ({ where }: any) => organizationMemberships.find((membership) =>
      membership.organizationId === where.organizationId
      && (!where.userId || membership.userId === where.userId)
      && membership.status === 'ACTIVE'
      && !membership.revokedAt) ?? null),
    findMany: mock(async ({ where }: any) => organizationMemberships.filter((membership) =>
      membership.organizationId === where.organizationId
      && membership.status === 'ACTIVE'
      && !membership.revokedAt)),
    count: mock(async ({ where }: any) => organizationMemberships.filter((membership) =>
      membership.organizationId === where.organizationId
      && membership.status === 'ACTIVE'
      && !membership.revokedAt).length),
    create: mock(async ({ data }: any) => {
      const user = (users as any)[data.userId];
      const membership = {
        id: `membership-${organizationMemberships.length + 1}`,
        ...data,
        status: 'ACTIVE',
        validFrom: now,
        validUntil: null,
        revokedAt: null,
        createdAt: now,
        user,
      };
      organizationMemberships.push(membership);
      return membership;
    }),
  },
  ethereumKey: {
    findFirst: mock(async ({ where }: any) => {
      const address = where.address.equals.toLowerCase();
      const user = Object.values(users).find((candidate) =>
        candidate.ethereumKeys.some((key) => key.address.toLowerCase() === address));
      if (!user) return null;
      return {
        address: user.ethereumKeys[0].address,
        userId: user.id,
        user: { emailVerified: user.emailVerified },
      };
    }),
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
    findFirst: mock(async ({ where }: any) => credentials.find((credential) =>
      credential.organizationId === where.organizationId
      && credential.id === where.id
      && (!('revokedAt' in where) || credential.revokedAt === where.revokedAt)
      && (!('kind' in where) || credential.kind === where.kind)) ?? null),
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
    redirectUris: ['https://alpha.example/callback'], type: 'spa', mode: 'TENANT_MANAGED', disabled: false, createdAt: now, updatedAt: now,
  }];
  credentials = [];
  webhooks = [{
    id: 'webhook-a', organizationId: 'org-a', url: 'https://alpha.example/webhooks',
    eventTypes: ['managed_account.created'], active: true, createdAt: now, updatedAt: now,
  }];
  organizationMemberships = [
    {
      id: 'admin-org-a', organizationId: 'org-a', userId: 'admin', role: 'ADMIN',
      status: 'ACTIVE', validFrom: now, validUntil: null, revokedAt: null, createdAt: now, user: users.admin,
    },
    {
      id: 'member-org-a', organizationId: 'org-a', userId: 'member', role: 'MEMBER',
      status: 'ACTIVE', validFrom: now, validUntil: null, revokedAt: null, createdAt: now, user: users.member,
    },
    {
      id: 'admin-org-b', organizationId: 'org-b', userId: 'admin-b', role: 'ADMIN',
      status: 'ACTIVE', validFrom: now, validUntil: null, revokedAt: null, createdAt: now, user: users['admin-b'],
    },
  ];
});

describe('tenant console boundary', () => {
  test('requires a session and permits MEMBER reads but not mutations', async () => {
    const router = await consoleRouter();
    expect((await router.request('/org-a/apps')).status).toBe(401);
    expect((await router.request('/org-a', { headers: { 'x-test-user': 'member' } })).status).toBe(200);
    expect((await router.request('/org-a/apps', { headers: { 'x-test-user': 'member' } })).status).toBe(200);
    expect((await router.request('/org-a/members', { headers: { 'x-test-user': 'member' } })).status).toBe(200);
    expect((await router.request('/org-a/apps', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'member' },
      body: JSON.stringify({ name: 'Nope', redirectUris: ['https://example.com/callback'] }),
    })).status).toBe(403);
    expect((await router.request('/org-a/members', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'member' },
      body: JSON.stringify({ address: users.target.ethereumKeys[0].address }),
    })).status).toBe(403);
  });

  test('adds a verified linked address as an administrator idempotently', async () => {
    const router = await consoleRouter();
    const created = await router.request('/org-a/members', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ address: users.target.ethereumKeys[0].address.toLowerCase() }),
    });
    expect(created.status).toBe(201);
    expect(await created.json()).toMatchObject({
      member: {
        userId: 'target',
        email: 'target@example.com',
        address: users.target.ethereumKeys[0].address,
        role: 'ADMIN',
      },
    });
    expect(apps[0].mode).toBe('TENANT_MANAGED');

    const repeated = await router.request('/org-a/members', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ address: users.target.ethereumKeys[0].address }),
    });
    expect(repeated.status).toBe(200);
    expect(organizationMemberships.filter((membership) => membership.userId === 'target')).toHaveLength(1);

    const listed = await router.request('/org-a/members', { headers: { 'x-test-user': 'admin' } });
    expect(listed.status).toBe(200);
    expect((await listed.json() as any).members).toHaveLength(3);
  });

  test('rejects invalid or unlinked addresses and enforces the member limit', async () => {
    const router = await consoleRouter();
    const invalid = await router.request('/org-a/members', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ address: 'not-an-address' }),
    });
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toMatchObject({ error: { code: 'INVALID_ADDRESS' } });

    const unlinked = await router.request('/org-a/members', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ address: '0x5555555555555555555555555555555555555555' }),
    });
    expect(unlinked.status).toBe(404);
    expect(await unlinked.json()).toMatchObject({ error: { code: 'OPENKEY_USER_NOT_FOUND' } });

    const first = await router.request('/org-a/members', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ address: users.target.ethereumKeys[0].address }),
    });
    expect(first.status).toBe(201);
    const overLimit = await router.request('/org-a/members', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ address: users.secondTarget.ethereumKeys[0].address }),
    });
    expect(overLimit.status).toBe(429);
    expect(await overLimit.json()).toMatchObject({ error: { code: 'PLAN_LIMIT_EXCEEDED' } });
  });

  test('hides organizations and resource IDs across tenant boundaries', async () => {
    const router = await consoleRouter();
    expect((await router.request('/org-b/apps', { headers: { 'x-test-user': 'admin' } })).status).toBe(404);
    expect((await router.request('/org-b/members', { headers: { 'x-test-user': 'admin' } })).status).toBe(404);
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
      body: JSON.stringify({ name: 'Production management credential' }),
    });
    expect(created.status).toBe(201);
    const creationBody = await created.json() as any;
    expect(creationBody.secret).toStartWith('oksk_');

    const rotated = await router.request(`/org-a/credentials/${creationBody.credential.id}/rotate`, {
      method: 'POST',
      headers: { 'x-test-user': 'admin' },
    });
    expect(rotated.status).toBe(201);
    expect((await rotated.json() as any).secret).toStartWith('oksk_');

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
    expect(await created.json()).toMatchObject({ client: { name: 'Beta app', disabled: false, mode: 'TENANT_MANAGED' } });

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
    expect(body.account).toMatchObject({ id: 'account-a', externalUserId: 'customer-a' });
    expect(body.account).not.toHaveProperty('managedAccountId');
    expect(body.account).not.toHaveProperty('ownerUserId');
    expect(body.account).not.toHaveProperty('keyId');
    expect(body.account).not.toHaveProperty('tenantParentDelegation');
    expect(body.account).not.toHaveProperty('ownerDid');
    expect(body.account).not.toHaveProperty('policyTemplate');
    expect(body.account).not.toHaveProperty('policyVersion');
    expect(body.account).not.toHaveProperty('tenantParentDelegationCid');

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

describe('management credential catalog', () => {
  test('rejects legacy broker/provisioner credential kinds on create', async () => {
    const router = await consoleRouter();
    const response = await router.request('/org-a/credentials', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-test-user': 'admin' },
      body: JSON.stringify({ name: 'Legacy broker', kind: 'BROKER' }),
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'INVALID_REQUEST' },
    });
  });
});
