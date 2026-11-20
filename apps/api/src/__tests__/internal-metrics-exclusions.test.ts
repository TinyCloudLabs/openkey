import { afterEach, expect, test } from 'bun:test';
import { mockModules } from './mock-module';

// TC-1480 + TC-2356: the shared SCOREBOARD_EXCLUSIONS list drives accounts.real/excluded and
// the `explicit_exclusions` bucket of the users block, so the two blocks agree on who is excluded.
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({}) }),
});

const { createInternalMetricsRouter } = await import('../routes/internal-metrics?tc1480-exclusions' as string);

const envKeys = ['SCOREBOARD_EXCLUSIONS', 'SCOREBOARD_EXCLUDE_USER_IDS', 'INTERNAL_METRICS_TOKEN'] as const;
const savedEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));
afterEach(() => {
  for (const key of envKeys) {
    if (savedEnv[key] === undefined) delete process.env[key]; else process.env[key] = savedEnv[key];
  }
});

const createdAt = new Date('2026-01-01T00:00:00.000Z');
const session = new Date(Date.now() - 2 * 24 * 3_600_000);
// Ten accounts with ordinary-looking addresses, all with a session; "list-1" and "list-2" are on the list.
const ids = [...Array.from({ length: 8 }, (_, i) => `user-${i}`), 'list-1', 'list-2'];
const emailOf = (id: string) => (id === 'list-1' ? 'zed@acme.io' : id === 'list-2' ? 'yan@acme.io' : `${id.replace('-', '')}@acme.io`);

function database() {
  const users = ids.map((id) => ({ id, email: emailOf(id), createdAt, ethereumKeys: [] }));
  return {
    user: { count: async () => users.length, findMany: async () => users },
    ethereumKey: { count: async () => 4, findMany: async () => [] },
    session: { groupBy: async () => ids.map((userId) => ({ userId, _max: { updatedAt: session } })) },
    oauthAccessToken: { findMany: async () => [] },
    oauthClient: { findMany: async () => [] },
    tinyCloudManageKeySigningDecision: { count: async () => 3, groupBy: async () => [] },
    tinyCloudManageKeyAppPreference: { count: async () => 2 },
    $queryRaw: async () => [],
  };
}

const getMetrics = async () => {
  process.env.INTERNAL_METRICS_TOKEN = 'internal-token';
  const router = createInternalMetricsRouter(() => database());
  return router.request('/', { headers: { Authorization: 'Bearer internal-token' } });
};

test('listed accounts are subtracted from accounts.real and from users.real', async () => {
  process.env.SCOREBOARD_EXCLUSIONS = JSON.stringify([
    { kind: 'email', value: 'zed@acme.io' },
    { kind: 'user_id', value: 'list-2' },
  ]);
  const res = await getMetrics();
  expect(res.status).toBe(200);
  const body = await res.json();
  expect(body.accounts).toMatchObject({ total: 10, real: 8, excluded: 2, excludedDomainOnly: 0 });
  expect(body.users).toMatchObject({ total: 10, real: 8 });
  expect(body.users.buckets.explicit_exclusions).toBe(2);
  expect(body.users.real).toBe(body.accounts.real);
});

test('a listed domain excludes its accounts from both blocks', async () => {
  process.env.SCOREBOARD_EXCLUSIONS = JSON.stringify([{ kind: 'email_domain', value: 'acme.io' }]);
  const body = await (await getMetrics()).json();
  expect(body.accounts).toMatchObject({ total: 10, real: 0, excluded: 10, excludedDomainOnly: 10 });
  expect(body.users.real).toBe(0);
});

test('the legacy user-id env still feeds explicit_exclusions beside the shared list', async () => {
  process.env.SCOREBOARD_EXCLUSIONS = JSON.stringify([{ kind: 'user_id', value: 'list-1' }]);
  process.env.SCOREBOARD_EXCLUDE_USER_IDS = 'list-2';
  const body = await (await getMetrics()).json();
  // accounts.* ignores the legacy env; users.* applies both.
  expect(body.accounts).toMatchObject({ real: 9, excluded: 1 });
  expect(body.users.buckets.explicit_exclusions).toBe(2);
  expect(body.users.real).toBe(8);
});

test('an invalid exclusion list keeps the totals, nulls the exclusion fields and the users block, and never echoes the list', async () => {
  process.env.SCOREBOARD_EXCLUSIONS = JSON.stringify([{ kind: 'email', value: 'leaky-value' }]);
  const quiet = console.error;
  console.error = () => {};
  try {
    const res = await getMetrics();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.accounts).toMatchObject({ total: 10, real: null, excluded: null, excludedDomainOnly: null });
    expect(body.users).toBeNull();
    expect(body.keys).toMatchObject({ total: 4 });
    expect(JSON.stringify(body)).not.toContain('leaky-value');
  } finally {
    console.error = quiet;
  }
});
