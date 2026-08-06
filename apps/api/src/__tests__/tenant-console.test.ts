import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';

const now = new Date('2026-08-05T12:00:00.000Z');
const users = {
  admin: { id: 'admin', email: 'admin@example.com', name: 'Admin', emailVerified: true },
  member: { id: 'member', email: 'member@example.com', name: 'Member', emailVerified: true },
  target: { id: 'target', email: 'target@example.com', name: 'Target', emailVerified: true },
};
let memberships: any[];
let apps: any[];
let serializationFailures = 0;
let transactions = 0;

const organization = { id: 'org-a', name: 'Alpha', plan: 'FREE', billingState: 'FREE', createdAt: now, updatedAt: now };
const entitlements = { id: 'ent-a', organizationId: 'org-a', version: 1, maxApps: 1, maxOrganizationMembers: 3, requestsPerMinute: 60, auditRetentionDays: 7, createdAt: now, updatedAt: now };

const db = {
  $transaction: async (operation: (tx: any) => any) => {
    transactions += 1;
    if (serializationFailures > 0) {
      serializationFailures -= 1;
      throw Object.assign(new Error('serialization failure'), { code: 'P2034' });
    }
    return operation(db);
  },
  organization: {
    findUnique: async ({ where }: any) => where.id === organization.id ? { ...organization, planEntitlements: entitlements } : null,
  },
  planEntitlements: { create: async () => entitlements },
  organizationMembership: {
    findFirst: async ({ where }: any) => memberships.find((candidate) => candidate.organizationId === where.organizationId
      && (!where.userId || candidate.userId === where.userId)
      && (!where.id || candidate.id === where.id)
      && candidate.status === 'ACTIVE' && !candidate.revokedAt) ?? null,
    findMany: async ({ where }: any) => memberships.filter((candidate) => candidate.organizationId === where.organizationId && candidate.status === 'ACTIVE' && !candidate.revokedAt),
    count: async ({ where }: any) => memberships.filter((candidate) => candidate.organizationId === where.organizationId && candidate.status === 'ACTIVE' && !candidate.revokedAt
      && (!where.role || candidate.role === where.role)).length,
    create: async ({ data }: any) => {
      const member = { id: `member-${memberships.length}`, ...data, status: 'ACTIVE', revokedAt: null, validFrom: now, validUntil: null, createdAt: now, user: users[data.userId as keyof typeof users] };
      memberships.push(member);
      return member;
    },
    update: async () => ({}),
  },
  ethereumKey: {
    findFirst: async ({ where }: any) => where.address.equals.toLowerCase() === '0x1111111111111111111111111111111111111111'
      ? { userId: 'target', user: { emailVerified: true } } : null,
  },
  oauthClient: {
    count: async ({ where }: any) => apps.filter((app) => app.organizationId === where.organizationId).length,
    findMany: async ({ where }: any) => apps.filter((app) => app.organizationId === where.organizationId),
    findFirst: async ({ where }: any) => apps.find((app) => app.id === where.id && app.organizationId === where.organizationId) ?? null,
    create: async ({ data }: any) => { const app = { ...data, createdAt: now, updatedAt: now }; apps.push(app); return app; },
    updateMany: async ({ where, data }: any) => {
      const app = apps.find((candidate) => candidate.id === where.id && candidate.organizationId === where.organizationId);
      if (!app) return { count: 0 };
      Object.assign(app, data);
      return { count: 1 };
    },
  },
};

mock.module('@openkey/db', () => ({ createPrismaClient: () => db }));

const session = createMiddleware(async (c, next) => {
  const userId = c.req.header('x-test-user');
  if (!userId || !(userId in users)) return c.json({ error: 'Unauthorized' }, 401);
  c.set('user', users[userId as keyof typeof users]);
  c.set('session', { id: `session-${userId}`, userId, expiresAt: new Date(Date.now() + 60_000) });
  await next();
});

mock.module('../middleware/session', () => ({ requireSession: session }));

async function router() {
  const { createTenantConsoleRouter } = await import('../routes/tenant-console');
  return createTenantConsoleRouter(db as any, { sessionMiddleware: session as any });
}
function json(userId: string, body: unknown) { return { method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': userId }, body: JSON.stringify(body) }; }

beforeEach(() => {
  memberships = [
    { id: 'admin-a', organizationId: 'org-a', userId: 'admin', role: 'ADMIN', status: 'ACTIVE', revokedAt: null, validFrom: now, validUntil: null, createdAt: now, user: users.admin },
    { id: 'member-a', organizationId: 'org-a', userId: 'member', role: 'MEMBER', status: 'ACTIVE', revokedAt: null, validFrom: now, validUntil: null, createdAt: now, user: users.member },
  ];
  apps = [];
  serializationFailures = 0;
  transactions = 0;
});

describe('developer organization console', () => {
  test('permits member reads but scopes mutations and IDs to the organization', async () => {
    const console = await router();
    expect((await console.request('/org-a/apps', { headers: { 'x-test-user': 'member' } })).status).toBe(200);
    expect((await console.request('/org-a/apps', json('member', { name: 'Nope', redirectUris: ['https://example.com/callback'] }))).status).toBe(403);
    expect((await console.request('/org-a/members/admin-a', { method: 'DELETE', headers: { 'x-test-user': 'admin' } })).status).toBe(409);
    expect((await console.request('/org-b/apps', { headers: { 'x-test-user': 'admin' } })).status).toBe(404);
    expect((await console.request('/org-a/apps/other', { method: 'PATCH', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' }, body: JSON.stringify({ disabled: true }) })).status).toBe(404);
  });

  test('rejects unsafe OAuth URLs on create and patch while enforcing the app limit', async () => {
    const console = await router();
    expect((await console.request('/org-a/apps', json('admin', { name: 'Unsafe', redirectUris: ['javascript:alert(1)'] }))).status).toBe(400);
    const created = await console.request('/org-a/apps', json('admin', { name: 'Safe', redirectUris: ['https://example.com/callback'], uri: 'https://example.com' }));
    expect(created.status).toBe(201);
    const app = (await created.json() as any).client;
    expect((await console.request(`/org-a/apps/${app.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json', 'x-test-user': 'admin' }, body: JSON.stringify({ icon: 'data:text/html,owned' }) })).status).toBe(400);
    expect((await console.request('/org-a/apps', json('admin', { name: 'Over limit', redirectUris: ['https://example.com/other'] }))).status).toBe(429);
  });

  test('retries member and app creation after a serializable transaction conflict', async () => {
    const console = await router();
    serializationFailures = 1;
    expect((await console.request('/org-a/members', json('admin', { address: '0x1111111111111111111111111111111111111111' }))).status).toBe(201);
    expect(transactions).toBe(2);
    apps = [];
    transactions = 0;
    serializationFailures = 1;
    expect((await console.request('/org-a/apps', json('admin', { name: 'Retried', redirectUris: ['https://example.com/callback'] }))).status).toBe(201);
    expect(transactions).toBe(2);
  });
});
