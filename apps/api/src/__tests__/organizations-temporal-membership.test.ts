import { expect, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { createOrganizationsRouter } from '../routes/organizations';

test('organization selection excludes expired and not-yet-valid memberships', async () => {
  const observed: any[] = [];
  const memberships = [
    { id: 'active', validFrom: new Date('2020-01-01'), validUntil: null },
    { id: 'expired', validFrom: new Date('2020-01-01'), validUntil: new Date('2021-01-01') },
    { id: 'future', validFrom: new Date('2999-01-01'), validUntil: null },
  ];
  const db = {
    organizationMembership: {
      findMany: async ({ where }: any) => {
        observed.push(where);
        return memberships.filter((membership) => membership.validFrom <= where.validFrom.lte
          && (membership.validUntil === null || membership.validUntil > where.OR[1].validUntil.gt))
          .map((membership) => ({
            role: 'ADMIN',
            organization: {
              id: `org-${membership.id}`, name: membership.id, plan: 'FREE', billingState: 'FREE',
              brokerDid: null, planEntitlements: null,
              _count: { oauthClients: 0, managedAccounts: 0, memberships: 1 },
            },
          }));
      },
    },
  } as any;
  const session = createMiddleware(async (c, next) => {
    c.set('user', { id: 'user', email: 'user@example.com' });
    c.set('session', { id: 'session', userId: 'user', expiresAt: new Date(Date.now() + 60_000) });
    await next();
  });
  const router = createOrganizationsRouter(db, session as any);
  const response = await router.request('/');
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ organizations: [{ id: 'org-active' }] });
  expect(observed[0]).toMatchObject({
    userId: 'user', status: 'ACTIVE', revokedAt: null,
    validFrom: { lte: expect.any(Date) },
    OR: [{ validUntil: null }, { validUntil: { gt: expect.any(Date) } }],
  });
});
