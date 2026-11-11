import { timingSafeEqual } from 'crypto';
import { Hono } from 'hono';
import { getPrisma } from '@openkey/db';
import { getAccountOriginRefusals } from '../log';

type MetricsCounter = { count(options?: Record<string, unknown>): Promise<number> };
type RenewalGroup = { clientId: string; _count: { _all: number }; _max: { createdAt: Date | null } };
type RenewalGrouping = { groupBy(options: Record<string, unknown>): Promise<RenewalGroup[]> };
export type MetricsDatabase = {
  user: MetricsCounter;
  ethereumKey: MetricsCounter;
  tinyCloudManageKeySigningDecision: MetricsCounter & RenewalGrouping;
  tinyCloudManageKeyAppPreference: MetricsCounter;
};

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
    accounts: { total: totalAccounts, new24h: newAccounts24h },
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
    // Process-local counts reset on restart and never include Origin values.
    originRefusals: getAccountOriginRefusals(),
  };
}

export async function collectNativeRenewalMetrics(database: MetricsDatabase, now = new Date()) {
  const since24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const since7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const where = { allowed: true, reason: { in: ['native_renew', 'native_renew_recovered'] } };
  const [dayGroups, weekGroups] = await Promise.all([
    database.tinyCloudManageKeySigningDecision.groupBy({
      by: ['clientId'], where: { ...where, createdAt: { gte: since24h } },
      _count: { _all: true }, _max: { createdAt: true },
    }),
    database.tinyCloudManageKeySigningDecision.groupBy({
      by: ['clientId'], where: { ...where, createdAt: { gte: since7d } },
      _count: { _all: true }, _max: { createdAt: true },
    }),
  ]);
  return {
    windowHours: [24, 168],
    clients: weekGroups.map((week) => ({
      clientId: week.clientId,
      renewals24h: dayGroups.find((day) => day.clientId === week.clientId)?._count._all ?? 0,
      renewals7d: week._count._all,
      lastRenewalAt: week._max.createdAt
        ? new Date(Math.floor(week._max.createdAt.getTime() / 3_600_000) * 3_600_000).toISOString()
        : null,
    })),
  };
}

export function createInternalMetricsRouter(getDatabase: () => MetricsDatabase) {
  const router = new Hono();

  router.get('/native-renewals', async (c) => {
    if (!process.env.INTERNAL_METRICS_TOKEN) return c.json({ error: 'Internal metrics are not configured' }, 503);
    if (!authorized(c.req.header('Authorization'))) return c.json({ error: 'Unauthorized' }, 401);
    c.header('Cache-Control', 'no-store');
    return c.json(await collectNativeRenewalMetrics(getDatabase()));
  });

  router.get('/', async (c) => {
    if (!process.env.INTERNAL_METRICS_TOKEN) {
      return c.json({ error: 'Internal metrics are not configured' }, 503);
    }

    if (!authorized(c.req.header('Authorization'))) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    return c.json(await collectInternalMetrics(getDatabase()));
  });

  return router;
}

export const internalMetricsRouter = createInternalMetricsRouter(
  () => getPrisma() as unknown as MetricsDatabase,
);
