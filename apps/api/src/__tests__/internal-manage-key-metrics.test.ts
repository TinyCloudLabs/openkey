import { afterEach, expect, test } from 'bun:test';
import { mockModules } from './mock-module';
import { SCOREBOARD_EXCLUSION_CRITERIA } from '../services/scoreboard-exclusions';

// The route captures this client when it loads; the route tests fill it in.
const routeDatabase: Record<string, unknown> = {};
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => routeDatabase }),
});

const envKeys = ['SCOREBOARD_EXCLUSIONS', 'INTERNAL_METRICS_TOKEN'] as const;
const savedEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));
afterEach(() => {
  for (const key of envKeys) {
    if (savedEnv[key] === undefined) delete process.env[key]; else process.env[key] = savedEnv[key];
  }
  for (const key of Object.keys(routeDatabase)) delete routeDatabase[key];
});

// Ten accounts; qa-1 and qa-2 are on the exclusion list.
const accounts = [...Array.from({ length: 8 }, (_, i) => `user-${i}`), 'qa-1', 'qa-2']
  .map((id) => ({ id, email: `${id}@example.com`, ethereumKeys: [] }));
const countOf = (n: number) => ({ count: async () => n });
const useRouteDatabase = () => Object.assign(routeDatabase, {
  user: { count: async () => accounts.length, findMany: async () => accounts },
  ethereumKey: countOf(4),
  tinyCloudManageKeySigningDecision: countOf(3),
  tinyCloudManageKeyAppPreference: countOf(2),
});
const getMetrics = async () => {
  process.env.INTERNAL_METRICS_TOKEN = 'internal-token';
  const { internalMetricsRouter } = await import('../routes/internal-metrics?tc492-metrics' as string);
  return internalMetricsRouter.request('/', { headers: { Authorization: 'Bearer internal-token' } });
};

test('internal metrics expose aggregate manage-key health without identity material', async () => {
  const userCounts = [10, 2, 8, 1];
  const keyCounts = [12, 10, 3, 8];
  const decisionCounts = [7, 5, 2];
  const preferenceCounts = [4, 3];
  const database = {
    user: { count: async () => userCounts.shift() },
    ethereumKey: { count: async () => keyCounts.shift() },
    tinyCloudManageKeySigningDecision: { count: async () => decisionCounts.shift() },
    tinyCloudManageKeyAppPreference: { count: async () => preferenceCounts.shift() },
  };
  const { collectInternalMetrics } = await import('../routes/internal-metrics?tc492-metrics' as string);
  const result = await collectInternalMetrics(
    database as unknown as Parameters<typeof collectInternalMetrics>[0],
    new Date('2026-08-05T21:00:00.000Z'),
  );
  expect(result.accounts).toMatchObject({ real: 10, excluded: 0 });
  expect(result).toEqual({
    generatedAt: '2026-08-05T21:00:00.000Z',
    accounts: { total: 10, new24h: 2, real: 10, excluded: 0, excludedDomainOnly: 0, exclusionCriteria: SCOREBOARD_EXCLUSION_CRITERIA },
    keys: { total: 12, active: 10, new24h: 3 },
    tinyCloudManageKey: {
      canonicalResolution: { eligibleUsers: 8, canonicalKeys: 8, missingCanonicalUsers: 1 },
      appGrants: { enabled: 4, disabled: 3 },
      signingDecisions24h: { total: 7, allowed: 5, denied: 2 },
    },
  });
  const serialized = JSON.stringify(result);
  for (const forbidden of ['userId', 'keyId', 'address', 'token', 'message', 'signature']) {
    expect(serialized).not.toContain(forbidden);
  }
});

test('internal metrics route: excluded accounts are subtracted from real', async () => {
  process.env.SCOREBOARD_EXCLUSIONS = JSON.stringify([{ kind: 'email', value: 'qa-1@example.com' }, { kind: 'user_id', value: 'qa-2' }]);
  useRouteDatabase();
  const res = await getMetrics();
  expect(res.status).toBe(200);
  expect((await res.json()).accounts).toMatchObject({ total: 10, real: 8, excluded: 2, excludedDomainOnly: 0 });
});

test('internal metrics route: an invalid exclusion list keeps the totals and nulls the exclusion fields', async () => {
  process.env.SCOREBOARD_EXCLUSIONS = JSON.stringify([{ kind: 'email', value: 'leaky-value' }]);
  useRouteDatabase();
  const res = await getMetrics();
  expect(res.status).toBe(200);
  const body = await res.json();
  expect(body.accounts).toMatchObject({ total: 10, real: null, excluded: null, excludedDomainOnly: null, exclusionCriteria: SCOREBOARD_EXCLUSION_CRITERIA });
  expect(body.keys).toMatchObject({ total: 4 });
  expect(JSON.stringify(body)).not.toContain('leaky-value');
});
