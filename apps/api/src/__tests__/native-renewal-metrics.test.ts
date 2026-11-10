import { expect, test } from 'bun:test';
import { createInternalMetricsRouter, collectNativeRenewalMetrics, type MetricsDatabase } from '../routes/internal-metrics';


const routeDatabase = {
  user: { count: async () => 0 },
  ethereumKey: { count: async () => 0 },
  tinyCloudManageKeySigningDecision: {
    count: async () => 0,
    groupBy: async () => [],
  },
  tinyCloudManageKeyAppPreference: { count: async () => 0 },
} as unknown as MetricsDatabase;

test('native renewal metrics group successful renewal decisions by client and window', async () => {
  const now = new Date('2026-11-09T12:30:00.000Z');
  const rows = [
    { clientId: 'public-client-a', reason: 'native_renew', allowed: true, createdAt: new Date('2026-11-09T10:15:00.000Z') },
    { clientId: 'public-client-a', reason: 'native_renew_recovered', allowed: true, createdAt: new Date('2026-11-08T09:00:00.000Z') },
    { clientId: 'public-client-b', reason: 'native_renew', allowed: true, createdAt: new Date('2026-11-03T13:00:00.000Z') },
    { clientId: 'public-client-a', reason: 'native_renew', allowed: true, createdAt: new Date('2026-11-01T00:00:00.000Z') },
    { clientId: 'public-client-a', reason: 'other', allowed: true, createdAt: new Date('2026-11-09T11:00:00.000Z') },
    { clientId: 'public-client-a', reason: 'native_renew', allowed: false, createdAt: new Date('2026-11-09T11:00:00.000Z') },
  ];
  const database = {
    tinyCloudManageKeySigningDecision: {
      groupBy: async (options: Record<string, any>) => {
        const since = options.where.createdAt.gte as Date;
        const selected = rows.filter((row) => row.allowed && ['native_renew', 'native_renew_recovered'].includes(row.reason) && row.createdAt >= since);
        const byClient = new Map<string, typeof selected>();
        for (const row of selected) byClient.set(row.clientId, [...(byClient.get(row.clientId) ?? []), row]);
        return [...byClient].map(([clientId, matches]) => ({
          clientId, _count: { _all: matches.length },
          _max: { createdAt: matches.reduce((latest, row) => row.createdAt > latest ? row.createdAt : latest, matches[0]!.createdAt) },
        }));
      },
    },
  } as unknown as MetricsDatabase;
  const result = await collectNativeRenewalMetrics(database, now);
  expect(result.windowHours).toEqual([24, 168]);
  expect(result.clients).toEqual([
    { clientId: 'public-client-a', renewals24h: 1, renewals7d: 2, lastRenewalAt: '2026-11-09T10:00:00.000Z' },
    { clientId: 'public-client-b', renewals24h: 0, renewals7d: 1, lastRenewalAt: '2026-11-03T13:00:00.000Z' },
  ]);
  expect(Object.keys(result.clients[0]!).sort()).toEqual(['clientId', 'lastRenewalAt', 'renewals24h', 'renewals7d']);
});

test('native renewal metrics response is not cacheable', async () => {
  const original = process.env.INTERNAL_METRICS_TOKEN;
  process.env.INTERNAL_METRICS_TOKEN = 'metrics-test-token';
  try {
    const router = createInternalMetricsRouter(() => routeDatabase);
    const response = await router.request('/native-renewals', {
      headers: { Authorization: 'Bearer metrics-test-token' },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
  } finally {
    if (original === undefined) delete process.env.INTERNAL_METRICS_TOKEN;
    else process.env.INTERNAL_METRICS_TOKEN = original;
  }
});
