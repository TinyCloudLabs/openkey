import { timingSafeEqual } from 'crypto';
import { Hono } from 'hono';
import { getPrisma } from '@openkey/db';
import { getAccountOriginRefusals, logError } from '../log';

type MetricsCounter = { count(options?: Record<string, unknown>): Promise<number> };
type RenewalGroup = { clientId: string; _count: { _all: number }; _max: { createdAt: Date | null } };
type RenewalGrouping = { groupBy(options: Record<string, unknown>): Promise<RenewalGroup[]> };
type UserRow = { id: string; email: string; createdAt: Date };
type SessionActivity = { userId: string; _max: { updatedAt: Date | null } };
export type MetricsDatabase = {
  user: MetricsCounter & { findMany(options: Record<string, unknown>): Promise<UserRow[]> };
  ethereumKey: MetricsCounter & { findMany(options: Record<string, unknown>): Promise<Array<{ userId: string | null }>> };
  session: { groupBy(options: Record<string, unknown>): Promise<SessionActivity[]> };
  tinyCloudManageKeySigningDecision: MetricsCounter & RenewalGrouping;
  tinyCloudManageKeyAppPreference: MetricsCounter;
  $queryRaw<T>(query: TemplateStringsArray, ...values: unknown[]): Promise<T>;
};

const DAY_MS = 24 * 60 * 60 * 1000;
// bot_like: this many sessions created on one UTC day, within the last 30 days.
const BOT_SESSIONS_PER_DAY = 50;

// Account bucket rules (TC-2356). Patterns are not secret. Buckets are
// exclusive and checked in this order; an account lands in the first match.
// Per-person exclusions (team members' personal accounts) come only from the
// SCOREBOARD_EXCLUDE_USER_IDS env list of user ids, never from code.
const INTERNAL_TEAM_DOMAIN = /^(tinycloud\.xyz|tinycloudlabs\.[a-z]+|gbafa\.com|openkey\.so|spruceid\.com)$/;
const INTERNAL_AGENT_OR_QA_NAME =
  /^(qa|agent|bot|probe|canary|smoke|e2e|test|ci|julie|courier|orchard|holden|naomi|amos|alex|bobbie|clarissa|fred|miller|avasarala)([^a-z]|$)/;
const TEST_OR_THROWAWAY_DOMAIN =
  /(^|\.)(example\.[a-z]+|test|invalid|localhost|mailinator\.com|guerrillamail\.[a-z]+|10minutemail\.[a-z]+|yopmail\.com|tempmail\.[a-z]+)$/;
const TEST_LIKE_NAME = /(test|qa|probe|canary|smoke|e2e|bot|agent|demo|dummy|fake)/;

export const USER_BUCKETS = [
  'internal_team_domain',
  'internal_agent_or_qa',
  'test_or_throwaway_domain',
  'plus_addressed',
  'test_like_name',
  'never_completed_signup',
  'explicit_exclusions',
  'bot_like',
] as const;
export type UserBucket = (typeof USER_BUCKETS)[number] | 'real';

export type AccountFacts = {
  id: string;
  email: string;
  hasSession: boolean;
  hasKey: boolean;
  botLike: boolean;
};

export type UserMetrics = {
  total: number;
  buckets: Record<(typeof USER_BUCKETS)[number], number>;
  real: number;
  realActive: { d1: number; d7: number; d30: number };
  realNew7d: number;
};

export function classifyAccount(account: AccountFacts, excludedUserIds: ReadonlySet<string>): UserBucket {
  const [local = '', domain = ''] = account.email.split('@');
  const lowerLocal = local.toLowerCase();
  const lowerDomain = domain.toLowerCase();
  if (INTERNAL_TEAM_DOMAIN.test(lowerDomain)) return 'internal_team_domain';
  if (INTERNAL_AGENT_OR_QA_NAME.test(lowerLocal)) return 'internal_agent_or_qa';
  if (TEST_OR_THROWAWAY_DOMAIN.test(lowerDomain)) return 'test_or_throwaway_domain';
  if (local.includes('+')) return 'plus_addressed';
  if (TEST_LIKE_NAME.test(lowerLocal)) return 'test_like_name';
  if (!account.hasSession && !account.hasKey) return 'never_completed_signup';
  if (excludedUserIds.has(account.id)) return 'explicit_exclusions';
  if (account.botLike) return 'bot_like';
  return 'real';
}

/** Counts only. Emails and ids are read in memory and never returned or logged. */
export async function collectUserMetrics(
  database: MetricsDatabase,
  env: Record<string, string | undefined> = process.env,
  now = new Date(),
): Promise<UserMetrics> {
  const excluded = new Set((env.SCOREBOARD_EXCLUDE_USER_IDS ?? '').split(',').map((item) => item.trim()).filter(Boolean));
  const since30d = new Date(now.getTime() - 30 * DAY_MS);
  const [users, sessions, keyOwners, botRows] = await Promise.all([
    database.user.findMany({ select: { id: true, email: true, createdAt: true } }),
    database.session.groupBy({ by: ['userId'], _max: { updatedAt: true } }),
    database.ethereumKey.findMany({ where: { userId: { not: null } }, distinct: ['userId'], select: { userId: true } }),
    database.$queryRaw<Array<{ userId: string }>>`
      SELECT DISTINCT "userId" FROM (
        SELECT "userId" FROM session
        WHERE "createdAt" >= ${since30d}
        GROUP BY "userId", date_trunc('day', "createdAt")
        HAVING count(*) >= ${BOT_SESSIONS_PER_DAY}
      ) bots`,
  ]);
  const lastActive = new Map(sessions.map((row) => [row.userId, row._max.updatedAt]));
  const hasKey = new Set(keyOwners.map((row) => row.userId));
  const botLike = new Set(botRows.map((row) => row.userId));

  const buckets = Object.fromEntries(USER_BUCKETS.map((bucket) => [bucket, 0])) as UserMetrics['buckets'];
  const realActive = { d1: 0, d7: 0, d30: 0 };
  let real = 0;
  let realNew7d = 0;
  for (const user of users) {
    const bucket = classifyAccount({
      id: user.id,
      email: user.email,
      hasSession: lastActive.has(user.id),
      hasKey: hasKey.has(user.id),
      botLike: botLike.has(user.id),
    }, excluded);
    if (bucket !== 'real') {
      buckets[bucket] += 1;
      continue;
    }
    real += 1;
    if (user.createdAt.getTime() >= now.getTime() - 7 * DAY_MS) realNew7d += 1;
    const last = lastActive.get(user.id)?.getTime();
    if (last === undefined) continue;
    if (last >= now.getTime() - DAY_MS) realActive.d1 += 1;
    if (last >= now.getTime() - 7 * DAY_MS) realActive.d7 += 1;
    if (last >= now.getTime() - 30 * DAY_MS) realActive.d30 += 1;
  }
  return { total: users.length, buckets, real, realActive, realNew7d };
}

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

    const database = getDatabase();
    const metrics = await collectInternalMetrics(database);
    // A failed users query must not take the existing counts down with it: the
    // consumer keeps its last good users block when this is null.
    const users = await collectUserMetrics(database).catch((error) => {
      logError('error', 'api_error', error);
      return null;
    });
    return c.json({ ...metrics, users });
  });

  return router;
}

export const internalMetricsRouter = createInternalMetricsRouter(
  () => getPrisma() as unknown as MetricsDatabase,
);
