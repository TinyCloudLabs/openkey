import { timingSafeEqual } from 'crypto';
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { InvalidScoreboardExclusionsError, resolveScoreboardExclusions, SCOREBOARD_EXCLUSION_CRITERIA, type ExclusionDatabase } from '../services/scoreboard-exclusions';

const prisma = createPrismaClient();

type MetricsCounter = { count(options?: Record<string, unknown>): Promise<number> };
export type MetricsDatabase = Omit<ExclusionDatabase, 'user'> & {
  user: MetricsCounter & ExclusionDatabase['user'];
  ethereumKey: MetricsCounter;
  tinyCloudManageKeySigningDecision: MetricsCounter;
  tinyCloudManageKeyAppPreference: MetricsCounter;
};

export const internalMetricsRouter = new Hono();

function authorized(authHeader: string | undefined): boolean {
  const token = process.env.INTERNAL_METRICS_TOKEN;
  if (!token) return false;
  if (!authHeader?.startsWith('Bearer ')) return false;

  const provided = authHeader.slice(7);
  const expectedBytes = Buffer.from(token);
  const providedBytes = Buffer.from(provided);
  if (expectedBytes.length !== providedBytes.length) return false;
  return timingSafeEqual(expectedBytes, providedBytes);
}

export async function collectInternalMetrics(database: MetricsDatabase, now = new Date()) {
  // An invalid exclusion list must not hide the totals the Worker stores: report them without the exclusion fields.
  const exclusions = await resolveScoreboardExclusions(database).catch((error: unknown) => {
    if (error instanceof InvalidScoreboardExclusionsError) return null;
    throw error;
  });
  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const [
    totalAccounts, newAccounts24h, totalKeys, activeKeys, newKeys24h,
    eligibleCanonicalUsers, missingCanonicalUsers, canonicalKeys,
    signingDecisions24h, signingAllows24h, signingDenials24h,
    enabledAppGrants, disabledAppGrants,
  ] = await Promise.all([
    database.user.count(),
    database.user.count({ where: { createdAt: { gte: since } } }),
    database.ethereumKey.count(),
    database.ethereumKey.count({ where: { archivedAt: null } }),
    database.ethereumKey.count({ where: { createdAt: { gte: since }, archivedAt: null } }),
    database.user.count({ where: { ethereumKeys: { some: { keyType: 'MANAGED', archivedAt: null } } } }),
    database.user.count({ where: {
      ethereumKeys: { some: { keyType: 'MANAGED', archivedAt: null } },
      NOT: { ethereumKeys: { some: { keyType: 'MANAGED', archivedAt: null, isCanonicalTinyCloud: true } } },
    } }),
    database.ethereumKey.count({ where: { keyType: 'MANAGED', archivedAt: null, isCanonicalTinyCloud: true } }),
    database.tinyCloudManageKeySigningDecision.count({ where: { createdAt: { gte: since } } }),
    database.tinyCloudManageKeySigningDecision.count({ where: { createdAt: { gte: since }, allowed: true } }),
    database.tinyCloudManageKeySigningDecision.count({ where: { createdAt: { gte: since }, allowed: false } }),
    database.tinyCloudManageKeyAppPreference.count({ where: { enabled: true, status: 'ENABLED' } }),
    database.tinyCloudManageKeyAppPreference.count({ where: { OR: [{ enabled: false }, { status: 'DISABLED' }] } }),
  ]);

  return {
    generatedAt: now.toISOString(),
    accounts: {
      total: totalAccounts, new24h: newAccounts24h,
      real: exclusions ? totalAccounts - exclusions.userIds.size : null,
      excluded: exclusions ? exclusions.userIds.size : null,
      excludedDomainOnly: exclusions ? exclusions.domainOnly : null,
      exclusionCriteria: SCOREBOARD_EXCLUSION_CRITERIA,
    },
    keys: { total: totalKeys, active: activeKeys, new24h: newKeys24h },
    tinyCloudManageKey: {
      canonicalResolution: {
        eligibleUsers: eligibleCanonicalUsers,
        canonicalKeys,
        missingCanonicalUsers,
      },
      appGrants: { enabled: enabledAppGrants, disabled: disabledAppGrants },
      signingDecisions24h: {
        total: signingDecisions24h,
        allowed: signingAllows24h,
        denied: signingDenials24h,
      },
    },
  };
}

internalMetricsRouter.get('/', async (c) => {
  if (!process.env.INTERNAL_METRICS_TOKEN) {
    return c.json({ error: 'Internal metrics are not configured' }, 503);
  }

  if (!authorized(c.req.header('Authorization'))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  return c.json(await collectInternalMetrics(prisma as unknown as MetricsDatabase));
});
