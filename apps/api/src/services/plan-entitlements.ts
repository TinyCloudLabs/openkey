import type { Plan, PrismaClient } from '@openkey/db';

type EntitlementDb = Pick<PrismaClient, 'organization' | 'planEntitlements'>;

export const PUBLIC_PLAN_ENTITLEMENTS = {
  FREE: {
    version: 1,
    maxApps: 1,
    maxOrganizationMembers: 3,
    requestsPerMinute: 60,
    auditRetentionDays: 7,
  },
  PRO: {
    version: 1,
    maxApps: 10,
    maxOrganizationMembers: 25,
    requestsPerMinute: 600,
    auditRetentionDays: 90,
  },
  ENTERPRISE: {
    version: 1,
    maxApps: 1_000,
    maxOrganizationMembers: 10_000,
    requestsPerMinute: 10_000,
    auditRetentionDays: 2_555,
  },
} as const;

export class EntitlementError extends Error {
  constructor(readonly code: 'PLAN_REQUIRES_AUDIT' | 'PLAN_LIMIT_EXCEEDED', message: string) {
    super(message);
    this.name = 'EntitlementError';
  }
}

export function publicPlanDefaults(plan: Plan) {
  if (plan === 'SCALE') {
    throw new EntitlementError('PLAN_REQUIRES_AUDIT', 'SCALE is not a public plan and requires an explicit migration');
  }
  return PUBLIC_PLAN_ENTITLEMENTS[plan];
}

export async function resolvePlanEntitlements(db: EntitlementDb, organizationId: string) {
  const organization = await db.organization.findUnique({
    where: { id: organizationId },
    select: { id: true, plan: true, planEntitlements: true },
  });
  if (!organization) return null;
  if (organization.planEntitlements) return { plan: organization.plan, ...organization.planEntitlements };

  const defaults = publicPlanDefaults(organization.plan);
  const entitlements = await db.planEntitlements.create({
    data: { organizationId, ...defaults },
  });
  return { plan: organization.plan, ...entitlements };
}

export function serializeEntitlements<T>(value: T) {
  return value;
}
