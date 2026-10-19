import { timingSafeEqual } from 'crypto';
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { logMetric } from '../log';

// TC-1483: counts-only metrics for the scoreboard, behind their own bearer
// (OPENKEY_METRICS_READ_TOKEN). The token grants aggregate counts only:
// responses never carry user ids, emails, addresses or origins, and no
// endpoint takes caller-chosen addresses. `GET /protocol-users` takes no input;
// OpenKey fetches the owner addresses (owners with data beyond the automatic `account` space; account-only owners excluded) itself from the node's
// read-only `GET /admin/stats` (NODE_STATS_URL + NODE_STATS_READ_TOKEN), maps
// them to accounts in memory, and returns `{count}`. Addresses are neither
// stored nor logged.

const prisma = createPrismaClient();

const MAX_ADDRESSES = 200_000;
const MAX_NODE_RESPONSE_BYTES = 16 * 1024 * 1024;
const NODE_STATS_TIMEOUT_MS = 15_000;
const PROTOCOL_USERS_LIMIT_PER_MINUTE = 30;
const RATE_WINDOW_MS = 60_000;
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

/**
 * Owner addresses with data beyond the automatic `account` space (account-only
 * owners are excluded), from the node's `GET /admin/stats`:
 *   200 { "owners": ["0x<40 hex>", ...] }
 * Any other status, a bad body, an oversized body, a timeout, a non-https URL
 * or missing config throws: callers answer 503 and never use a partial list.
 * Concurrent calls share one in-flight node request.
 */
export function fetchNodeOwners(
  env: Record<string, string | undefined> = process.env,
  fetchImpl: typeof fetch = fetch,
): Promise<string[]> {
  if (!inflightOwners) {
    inflightOwners = loadNodeOwners(env, fetchImpl).finally(() => { inflightOwners = null; });
  }
  return inflightOwners;
}

let inflightOwners: Promise<string[]> | null = null;

function assertAllowedStatsUrl(raw: string, env: Record<string, string | undefined>): void {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error('node stats url invalid'); }
  if (url.protocol === 'https:') return;
  const localDev = env.NODE_ENV === 'development'
    && url.protocol === 'http:'
    && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
  if (!localDev) throw new Error('node stats url must be https');
}

async function readCappedBody(response: Response): Promise<string> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_NODE_RESPONSE_BYTES) {
    await response.body?.cancel().catch(() => {});
    throw new Error('node stats response too large');
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_NODE_RESPONSE_BYTES) {
      await reader.cancel().catch(() => {});
      throw new Error('node stats response too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function loadNodeOwners(
  env: Record<string, string | undefined>,
  fetchImpl: typeof fetch,
): Promise<string[]> {
  const url = env.NODE_STATS_URL;
  const token = env.NODE_STATS_READ_TOKEN;
  if (!url || !token) throw new Error('node stats not configured');
  assertAllowedStatsUrl(url, env);
  const response = await fetchImpl(url, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Accept-Encoding': 'identity' },
    // Bun's fetch inflates gzip before the stream reader; the byte cap must see wire bytes.
    decompress: false,
    redirect: 'error',
    signal: AbortSignal.timeout(NODE_STATS_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error('node stats request failed');
  const encoding = response.headers.get('content-encoding')?.trim().toLowerCase();
  if (encoding && encoding !== 'identity') {
    await response.body?.cancel().catch(() => {});
    throw new Error('node stats response encoded');
  }
  const body = JSON.parse(await readCappedBody(response)) as { owners?: unknown } | null;
  const owners = body?.owners;
  if (
    !Array.isArray(owners)
    || owners.length > MAX_ADDRESSES
    || owners.some((owner) => typeof owner !== 'string' || !ADDRESS_PATTERN.test(owner))
  ) {
    throw new Error('node stats response invalid');
  }
  return owners as string[];
}

let rateWindowStart = 0;
let rateWindowCalls = 0;

/** Per-process fixed-window cap on `GET /protocol-users`. True when the call may proceed. */
function takeProtocolUsersSlot(now = Date.now()): boolean {
  if (now - rateWindowStart >= RATE_WINDOW_MS) {
    rateWindowStart = now;
    rateWindowCalls = 0;
  }
  rateWindowCalls += 1;
  return rateWindowCalls <= PROTOCOL_USERS_LIMIT_PER_MINUTE;
}

/** Test hook. */
export function resetScoreboardRateLimitForTests(): void {
  rateWindowStart = 0;
  rateWindowCalls = 0;
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

scoreboardMetricsRouter.get('/protocol-users', async (c) => {
  if (!takeProtocolUsersSlot()) {
    logMetric('warn', 'scoreboard_protocol_users_call', { status: 429 });
    return c.json({ error: 'Rate limit exceeded' }, 429);
  }
  let owners: string[];
  try {
    owners = await fetchNodeOwners();
  } catch {
    logMetric('warn', 'scoreboard_protocol_users_call', { status: 503 });
    return c.json({ error: 'Node stats unavailable' }, 503);
  }
  let count: number;
  try {
    count = await countProtocolUsers(prisma as unknown as ScoreboardDatabase, owners, exclusionsFromEnv());
  } catch (error) {
    logMetric('error', 'scoreboard_protocol_users_call', { status: 500 });
    throw error;
  }
  logMetric('info', 'scoreboard_protocol_users_call', { status: 200, count });
  return c.json({ count });
});

scoreboardMetricsRouter.get('/app-users', async (c) => {
  const counts = await countAppUsers(prisma as unknown as ScoreboardDatabase, exclusionsFromEnv());
  return c.json(counts);
});
