import type { Plan, PrismaClient } from '@openkey/db';

type EntitlementDb = Pick<PrismaClient, 'organization' | 'planEntitlements'>;

export const PUBLIC_PLAN_ENTITLEMENTS = {
  FREE: {
    version: 1,
    maxApps: 1,
    maxOrganizationMembers: 3,
    maxManagedAccounts: 100,
    monthlyActiveManagedUsers: 100,
    storageBytesPerManagedAccount: 100_000_000n,
    requestsPerMinute: 60,
    maxTenantDelegationTtlSeconds: 3_600,
    maxTenantPolicyVersion: 1,
    webhookDelivery: true,
    auditRetentionDays: 7,
  },
  PRO: {
    version: 1,
    maxApps: 10,
    maxOrganizationMembers: 25,
    maxManagedAccounts: 10_000,
    monthlyActiveManagedUsers: 10_000,
    storageBytesPerManagedAccount: 10_000_000_000n,
    requestsPerMinute: 600,
    maxTenantDelegationTtlSeconds: 86_400,
    maxTenantPolicyVersion: 5,
    webhookDelivery: true,
    auditRetentionDays: 90,
  },
  ENTERPRISE: {
    version: 1,
    maxApps: 1_000,
    maxOrganizationMembers: 10_000,
    maxManagedAccounts: 10_000_000,
    monthlyActiveManagedUsers: 10_000_000,
    storageBytesPerManagedAccount: 1_000_000_000_000n,
    requestsPerMinute: 10_000,
    maxTenantDelegationTtlSeconds: 604_800,
    maxTenantPolicyVersion: 100,
    webhookDelivery: true,
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

export function serializeEntitlements<T extends { storageBytesPerManagedAccount: bigint }>(value: T) {
  return { ...value, storageBytesPerManagedAccount: value.storageBytesPerManagedAccount.toString() };
}
