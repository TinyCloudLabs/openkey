import { timingSafeEqual } from 'crypto';
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';

// TC-1483: counts-only metrics for the scoreboard, behind their own read-only
// bearer (OPENKEY_METRICS_READ_TOKEN). Responses never carry user ids, emails,
// addresses or origins. Addresses arrive in the request body, are mapped in
// memory, and are not stored or logged.

const prisma = createPrismaClient();

const MAX_ADDRESSES = 200_000;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const ACTIVE_WINDOW_DAYS = 7;

type UserIdRow = { userId: string };
type DistinctUsers = {
  findMany(args: Record<string, unknown>): Promise<UserIdRow[]>;
};

export type ScoreboardDatabase = {
  $queryRaw<T>(query: TemplateStringsArray, ...values: unknown[]): Promise<T>;
  oauthAccessToken: DistinctUsers;
  oauthRefreshToken: DistinctUsers;
  oauthConsent: DistinctUsers;
  appSignInDay: DistinctUsers;
};

export type ScoreboardExclusions = { userIds: ReadonlySet<string>; clientIds: ReadonlySet<string> };

function parseList(value: string | undefined): Set<string> {
  return new Set((value ?? '').split(',').map((item) => item.trim()).filter(Boolean));
}

/** Team, QA and agent accounts: config lists, never returned by the API. */
export function exclusionsFromEnv(env: Record<string, string | undefined> = process.env): ScoreboardExclusions {
  return {
    userIds: parseList(env.SCOREBOARD_EXCLUDE_USER_IDS),
    clientIds: parseList(env.SCOREBOARD_EXCLUDE_CLIENT_IDS),
  };
}

function authorized(authHeader: string | undefined): boolean {
  const token = process.env.OPENKEY_METRICS_READ_TOKEN;
  if (!token || !authHeader?.startsWith('Bearer ')) return false;
  const expected = Buffer.from(token);
  const provided = Buffer.from(authHeader.slice(7));
  return expected.length === provided.length && timingSafeEqual(expected, provided);
}

/** Distinct accounts owning at least one of `addresses`, minus excluded accounts. */
export async function countProtocolUsers(
  database: ScoreboardDatabase,
  addresses: readonly string[],
  exclusions: ScoreboardExclusions,
): Promise<number> {
  const lowered = [...new Set(addresses.map((address) => address.toLowerCase()))];
  if (lowered.length === 0) return 0;
  // Includes archived keys: their data still exists. Orphan keys (userId NULL) are dropped.
  const rows = await database.$queryRaw<UserIdRow[]>`
    SELECT DISTINCT "userId" FROM ethereum_keys
    WHERE "userId" IS NOT NULL AND lower(address) = ANY(${lowered})`;
  return new Set(rows.map((row) => row.userId).filter((id) => !exclusions.userIds.has(id))).size;
}

export async function countAppUsers(
  database: ScoreboardDatabase,
  exclusions: ScoreboardExclusions,
  now = new Date(),
): Promise<{ total: number; active7d: number }> {
  const since = new Date(now.getTime() - ACTIVE_WINDOW_DAYS * 24 * 60 * 60 * 1000);
  const sinceDay = new Date(Date.UTC(since.getUTCFullYear(), since.getUTCMonth(), since.getUTCDate()));
  const userNotExcluded = { userId: { notIn: [...exclusions.userIds] } };
  const oauthWhere = { ...userNotExcluded, clientId: { notIn: [...exclusions.clientIds] } };
  const select = { userId: true };
  const distinct = ['userId'];

  const [accessEver, refreshEver, consentEver, signInEver, accessRecent, refreshRecent, consentRecent, signInRecent] =
    await Promise.all([
      database.oauthAccessToken.findMany({ where: oauthWhere, distinct, select }),
      database.oauthRefreshToken.findMany({ where: oauthWhere, distinct, select }),
      database.oauthConsent.findMany({ where: oauthWhere, distinct, select }),
      database.appSignInDay.findMany({ where: userNotExcluded, distinct, select }),
      database.oauthAccessToken.findMany({ where: { ...oauthWhere, createdAt: { gte: since } }, distinct, select }),
      database.oauthRefreshToken.findMany({ where: { ...oauthWhere, createdAt: { gte: since } }, distinct, select }),
      database.oauthConsent.findMany({ where: { ...oauthWhere, createdAt: { gte: since } }, distinct, select }),
      database.appSignInDay.findMany({ where: { ...userNotExcluded, day: { gte: sinceDay } }, distinct, select }),
    ]);
  const union = (...sets: UserIdRow[][]) => new Set(sets.flat().map((row) => row.userId)).size;
  return {
    total: union(accessEver, refreshEver, consentEver, signInEver),
    active7d: union(accessRecent, refreshRecent, consentRecent, signInRecent),
  };
}

export const scoreboardMetricsRouter = new Hono();

scoreboardMetricsRouter.use('*', async (c, next) => {
  if (!process.env.OPENKEY_METRICS_READ_TOKEN) {
    return c.json({ error: 'Scoreboard metrics are not configured' }, 503);
  }
  if (!authorized(c.req.header('Authorization'))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  await next();
});

scoreboardMetricsRouter.post('/protocol-users', async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Body must be JSON' }, 400);
  }
  const addresses = (body as { addresses?: unknown } | null)?.addresses;
  if (
    !Array.isArray(addresses)
    || addresses.length > MAX_ADDRESSES
    || addresses.some((address) => typeof address !== 'string' || !ADDRESS_PATTERN.test(address))
  ) {
    return c.json({ error: `addresses must be an array of at most ${MAX_ADDRESSES} 0x addresses` }, 400);
  }
  const count = await countProtocolUsers(prisma as unknown as ScoreboardDatabase, addresses, exclusionsFromEnv());
  return c.json({ count });
});

scoreboardMetricsRouter.get('/app-users', async (c) => {
  const counts = await countAppUsers(prisma as unknown as ScoreboardDatabase, exclusionsFromEnv());
  return c.json(counts);
});
