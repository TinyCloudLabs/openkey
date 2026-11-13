import { expect, test } from 'bun:test';
import { recordAccountOriginRefused } from '../log';
import { mockModules } from './mock-module';

await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({}) }),
});

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
  expect(result).toEqual({
    generatedAt: '2026-08-05T21:00:00.000Z',
    originRefusals: { since: expect.any(String), counts: expect.any(Array) },
    accounts: { total: 10, new24h: 2 },
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
test('internal metrics expose process-local origin refusal counts and preserve endpoint authorization statuses', async () => {
  const database = {
    user: { count: async () => 0, findMany: async () => [] },
    ethereumKey: { count: async () => 0, findMany: async () => [] },
    session: { groupBy: async () => [] },
    tinyCloudManageKeySigningDecision: { count: async () => 0 },
    tinyCloudManageKeyAppPreference: { count: async () => 0 },
    $queryRaw: async () => [],
  };
  const { createInternalMetricsRouter, collectInternalMetrics } = await import('../routes/internal-metrics?origin-refusals' as string);
  const route = '/api/internal/origin-refusal-metrics-test';
  recordAccountOriginRefused(route, 'foreign');
  const metrics = await collectInternalMetrics(
    database as unknown as Parameters<typeof collectInternalMetrics>[0],
  );
  expect(metrics.originRefusals.counts).toContainEqual({ route, reason: 'foreign', count: expect.any(Number) });
  expect(new Date(metrics.originRefusals.since).toISOString()).toBe(metrics.originRefusals.since);

  const router = createInternalMetricsRouter(() => database as unknown as Parameters<typeof collectInternalMetrics>[0]);
  const savedToken = process.env.INTERNAL_METRICS_TOKEN;
  try {
    delete process.env.INTERNAL_METRICS_TOKEN;
    expect((await router.request('/')).status).toBe(503);
    expect(await (await router.request('/')).json()).toEqual({ error: 'Internal metrics are not configured' });
    process.env.INTERNAL_METRICS_TOKEN = 'test-metrics-token';
    expect((await router.request('/', { headers: { authorization: 'Bearer wrong' } })).status).toBe(401);
    const response = await router.request('/', { headers: { authorization: 'Bearer test-metrics-token' } });
    expect(response.status).toBe(200);
    expect((await response.json()).originRefusals).toEqual(metrics.originRefusals);
  } finally {
    if (savedToken === undefined) delete process.env.INTERNAL_METRICS_TOKEN;
    else process.env.INTERNAL_METRICS_TOKEN = savedToken;
  }
});
