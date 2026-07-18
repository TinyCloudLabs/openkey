import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import { PUBLIC_PLAN_ENTITLEMENTS, serializeEntitlements } from '../services/plan-entitlements';

const prisma = createPrismaClient();
export const organizationsRouter = new Hono<SessionContext>();
organizationsRouter.use('*', requireSession);

organizationsRouter.get('/', async (c) => {
  const memberships = await prisma.organizationMembership.findMany({
    where: { userId: c.get('user').id, status: 'ACTIVE', revokedAt: null },
    select: {
      role: true,
      organization: {
        include: {
          planEntitlements: true,
          _count: { select: { oauthClients: true, managedAccounts: true, memberships: true } },
        },
      },
    },
    orderBy: { createdAt: 'asc' },
  });
  return c.json({
    organizations: memberships.map(({ organization, role }) => ({
      id: organization.id,
      name: organization.name,
      role,
      plan: organization.plan,
      billingState: organization.billingState,
      brokerDid: organization.brokerDid,
      entitlements: organization.planEntitlements ? serializeEntitlements(organization.planEntitlements) : null,
      usage: {
        apps: organization._count.oauthClients,
        managedAccounts: organization._count.managedAccounts,
        members: organization._count.memberships,
      },
    })),
  });
});

organizationsRouter.post('/', async (c) => {
  const body: { name?: unknown; brokerDid?: unknown } = await c.req.json().catch(() => ({}));
  if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 100
    || typeof body.brokerDid !== 'string' || !body.brokerDid.startsWith('did:')) {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'name and a broker DID are required' } }, 400);
  }
  const name = body.name.trim();
  const brokerDid = body.brokerDid;
  const organization = await prisma.$transaction(async (tx) => {
    const created = await tx.organization.create({
      data: { name, brokerDid, plan: 'FREE' },
    });
    await tx.organizationMembership.create({
      data: { organizationId: created.id, userId: c.get('user').id, role: 'ADMIN' },
    });
    await tx.planEntitlements.create({
      data: { organizationId: created.id, ...PUBLIC_PLAN_ENTITLEMENTS.FREE },
    });
    return created;
  });
  return c.json({ organization }, 201);
});
