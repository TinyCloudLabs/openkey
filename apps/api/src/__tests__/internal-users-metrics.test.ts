import { expect, test } from 'bun:test';
import { mockModules } from './mock-module';

await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({}) }),
});

const { classifyAccount, collectUserMetrics, createInternalMetricsRouter, USER_BUCKETS } = await import(
  '../routes/internal-metrics?tc2356-users' as string
);

const now = new Date('2026-11-13T12:00:00.000Z');
const hoursAgo = (hours: number) => new Date(now.getTime() - hours * 3_600_000);
const daysAgo = (days: number) => hoursAgo(days * 24);

type Account = { id: string; email: string; createdAt?: Date; lastSession?: Date; key?: boolean };

function fakeDatabase(accounts: Account[], botUserIds: string[] = []) {
  const rawCalls: unknown[][] = [];
  const database = {
    user: {
      count: async () => accounts.length,
      findMany: async () => accounts.map((a) => ({ id: a.id, email: a.email, createdAt: a.createdAt ?? daysAgo(100) })),
    },
    session: {
      groupBy: async () => accounts
        .filter((a) => a.lastSession)
        .map((a) => ({ userId: a.id, _max: { updatedAt: a.lastSession! } })),
    },
    ethereumKey: {
      count: async () => 0,
      findMany: async () => accounts.filter((a) => a.key).map((a) => ({ userId: a.id })),
    },
    tinyCloudManageKeySigningDecision: { count: async () => 0, groupBy: async () => [] },
    tinyCloudManageKeyAppPreference: { count: async () => 0 },
    async $queryRaw(_query: TemplateStringsArray, ...values: unknown[]) {
      rawCalls.push(values);
      return botUserIds.map((userId) => ({ userId }));
    },
  };
  return { database, rawCalls };
}

const session = daysAgo(2);

// One account per bucket. Several also match later rules (for example the team
// domain addresses start with qa/agent, the plus address contains "test"), so a
// wrong order would move them.
const accounts: Account[] = [
  { id: 'u-team', email: 'qa@tinycloud.xyz', lastSession: session },
  { id: 'u-team-case', email: 'Someone@TinyCloudLabs.com', lastSession: session },
  { id: 'u-agent', email: 'agent@gmail.com', lastSession: session },
  { id: 'u-agent-digit', email: 'qa2@gmail.com', lastSession: session },
  { id: 'u-throwaway', email: 'testing-person@mailinator.com', lastSession: session },
  { id: 'u-subdomain', email: 'jane@mail.example.com', lastSession: session },
  { id: 'u-plus', email: 'jane+test@gmail.com', lastSession: session },
  { id: 'u-testlike', email: 'mydemo@gmail.com', lastSession: session },
  { id: 'u-never', email: 'ghost@gmail.com' },
  { id: 'u-never-listed', email: 'ghost2@gmail.com' },
  { id: 'u-explicit', email: 'teammate.personal@gmail.com', lastSession: session },
  { id: 'u-bot', email: 'scraper@gmail.com', lastSession: session },
  { id: 'u-real-session', email: 'alice@gmail.com', lastSession: session },
  { id: 'u-real-key', email: 'bob@proton.me', key: true },
];

test('each account lands in exactly one bucket, in precedence order', async () => {
  const { database } = fakeDatabase(accounts, ['u-bot']);
  const result = await collectUserMetrics(database, { SCOREBOARD_EXCLUDE_USER_IDS: 'u-explicit,u-never-listed' }, now);
  expect(result.buckets).toEqual({
    internal_team_domain: 2,
    internal_agent_or_qa: 2,
    test_or_throwaway_domain: 2,
    plus_addressed: 1,
    test_like_name: 1,
    never_completed_signup: 2, // listed in env, but never_completed_signup is checked first
    explicit_exclusions: 1,
    bot_like: 1,
  });
  expect(result.total).toBe(accounts.length);
  expect(result.real).toBe(2);
  const bucketed = Object.values(result.buckets as Record<string, number>).reduce((sum, n) => sum + n, 0);
  expect(bucketed + result.real).toBe(result.total);
  expect(Object.keys(result.buckets)).toEqual([...USER_BUCKETS]);
});

test('classifyAccount: earlier rules win over later ones', () => {
  const facts = { hasSession: true, hasKey: false, botLike: true };
  const classify = (email: string, excluded: string[] = []) =>
    classifyAccount({ id: 'x', email, ...facts }, new Set(excluded));
  expect(classify('qa+1@openkey.so')).toBe('internal_team_domain');
  expect(classify('test+1@gmail.com')).toBe('internal_agent_or_qa');
  expect(classify('person+1@example.org')).toBe('test_or_throwaway_domain');
  expect(classify('person+demo@gmail.com')).toBe('plus_addressed');
  expect(classify('demo.person@gmail.com')).toBe('test_like_name');
  expect(classify('person@gmail.com', ['x'])).toBe('explicit_exclusions');
  expect(classify('person@gmail.com')).toBe('bot_like');
  expect(classifyAccount({ id: 'x', email: 'person@gmail.com', hasSession: false, hasKey: false, botLike: true }, new Set(['x'])))
    .toBe('never_completed_signup');
  expect(classifyAccount({ id: 'x', email: 'person@gmail.com', hasSession: false, hasKey: true, botLike: false }, new Set()))
    .toBe('real');
  // Agent-name rule needs a boundary: "alexander" is not "alex".
  expect(classify('alexander@gmail.com')).toBe('bot_like');
});

test('env exclusions: ids are trimmed, unknown ids are harmless, empty or unset env excludes nobody', async () => {
  const people: Account[] = [
    { id: 'a', email: 'alice@gmail.com', lastSession: session },
    { id: 'b', email: 'bob@gmail.com', lastSession: session },
    { id: 'c', email: 'carol@gmail.com', lastSession: session },
  ];
  const { database } = fakeDatabase(people);
  const listed = await collectUserMetrics(database, { SCOREBOARD_EXCLUDE_USER_IDS: ' a , ,b,,no-such-user ' }, now);
  expect(listed.buckets.explicit_exclusions).toBe(2);
  expect(listed.real).toBe(1);
  for (const env of [{ SCOREBOARD_EXCLUDE_USER_IDS: '' }, { SCOREBOARD_EXCLUDE_USER_IDS: ' , ' }, {}]) {
    const result = await collectUserMetrics(database, env, now);
    expect(result.buckets.explicit_exclusions).toBe(0);
    expect(result.real).toBe(3);
  }
});

test('bot_like: the query counts >=50 sessions in one day over the last 30 days, and bots leave REAL', async () => {
  const people: Account[] = [
    { id: 'bot', email: 'scraper@gmail.com', createdAt: daysAgo(1), lastSession: hoursAgo(1) },
    { id: 'human', email: 'alice@gmail.com', createdAt: daysAgo(1), lastSession: hoursAgo(1) },
  ];
  const { database, rawCalls } = fakeDatabase(people, ['bot']);
  const result = await collectUserMetrics(database, {}, now);
  expect(rawCalls).toHaveLength(1);
  const [since, threshold] = rawCalls[0] as [Date, number];
  expect(since.toISOString()).toBe(daysAgo(30).toISOString());
  expect(threshold).toBe(50);
  expect(result.buckets.bot_like).toBe(1);
  expect(result).toMatchObject({ real: 1, realActive: { d1: 1, d7: 1, d30: 1 }, realNew7d: 1 });
});

test('REAL activity windows and new-7d use only real accounts', async () => {
  const people: Account[] = [
    { id: 'r1', email: 'a1@gmail.com', createdAt: daysAgo(6), lastSession: hoursAgo(12) },
    { id: 'r7', email: 'a7@gmail.com', createdAt: daysAgo(8), lastSession: daysAgo(3) },
    { id: 'r30', email: 'a30@gmail.com', createdAt: daysAgo(50), lastSession: daysAgo(20) },
    { id: 'r-old', email: 'a-old@gmail.com', createdAt: daysAgo(50), lastSession: daysAgo(40) },
    { id: 'r-key', email: 'a-key@gmail.com', createdAt: daysAgo(2), key: true },
    // Internal account that is new and active: counted in no REAL figure.
    { id: 'team', email: 'x@tinycloud.xyz', createdAt: daysAgo(1), lastSession: hoursAgo(1) },
  ];
  const { database } = fakeDatabase(people);
  const result = await collectUserMetrics(database, {}, now);
  expect(result.real).toBe(5);
  expect(result.realActive).toEqual({ d1: 1, d7: 2, d30: 3 });
  expect(result.realNew7d).toBe(2);
});

test('empty database yields zeros', async () => {
  const { database } = fakeDatabase([]);
  const result = await collectUserMetrics(database, {}, now);
  expect(result).toEqual({
    total: 0,
    buckets: Object.fromEntries(USER_BUCKETS.map((bucket: string) => [bucket, 0])),
    real: 0,
    realActive: { d1: 0, d7: 0, d30: 0 },
    realNew7d: 0,
  });
});

test('the response carries counts only: no emails, ids or per-user data', async () => {
  const { database } = fakeDatabase(accounts, ['u-bot']);
  const result = await collectUserMetrics(database, { SCOREBOARD_EXCLUDE_USER_IDS: 'u-explicit' }, now);
  const serialized = JSON.stringify(result);
  for (const account of accounts) {
    expect(serialized).not.toContain(account.id);
    expect(serialized).not.toContain(account.email);
    expect(serialized).not.toContain(account.email.split('@')[1]!.toLowerCase());
  }
  expect(serialized).not.toContain('@');
  expect(serialized).not.toContain('u-explicit');
  const numbers: unknown[] = [];
  const walk = (value: unknown) => {
    if (value && typeof value === 'object') Object.values(value).forEach(walk);
    else numbers.push(value);
  };
  walk(result);
  expect(numbers.every((value) => Number.isInteger(value))).toBe(true);
  expect(Object.keys(result)).toEqual(['total', 'buckets', 'real', 'realActive', 'realNew7d']);
});

test('GET / keeps its token gate and adds the users block next to the existing counts', async () => {
  const { database } = fakeDatabase(accounts, ['u-bot']);
  const router = createInternalMetricsRouter(() => database);
  const savedToken = process.env.INTERNAL_METRICS_TOKEN;
  const savedExclusions = process.env.SCOREBOARD_EXCLUDE_USER_IDS;
  try {
    delete process.env.INTERNAL_METRICS_TOKEN;
    expect((await router.request('/')).status).toBe(503);
    process.env.INTERNAL_METRICS_TOKEN = 'test-metrics-token';
    expect((await router.request('/')).status).toBe(401);
    expect((await router.request('/', { headers: { authorization: 'Bearer wrong' } })).status).toBe(401);

    process.env.SCOREBOARD_EXCLUDE_USER_IDS = 'u-explicit';
    const response = await router.request('/', { headers: { authorization: 'Bearer test-metrics-token' } });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.accounts).toEqual({ total: accounts.length, new24h: accounts.length });
    expect(body.keys).toBeDefined();
    expect(body.users.total).toBe(accounts.length);
    expect(body.users.buckets.explicit_exclusions).toBe(1);
    expect(body.users.real).toBe(2);
    expect(JSON.stringify(body)).not.toContain('u-explicit');
  } finally {
    if (savedToken === undefined) delete process.env.INTERNAL_METRICS_TOKEN;
    else process.env.INTERNAL_METRICS_TOKEN = savedToken;
    if (savedExclusions === undefined) delete process.env.SCOREBOARD_EXCLUDE_USER_IDS;
    else process.env.SCOREBOARD_EXCLUDE_USER_IDS = savedExclusions;
  }
});

test('a failing users query returns users: null and leaves the existing counts intact', async () => {
  const { database } = fakeDatabase(accounts);
  database.session.groupBy = async () => { throw new Error('boom'); };
  const router = createInternalMetricsRouter(() => database);
  const savedToken = process.env.INTERNAL_METRICS_TOKEN;
  try {
    process.env.INTERNAL_METRICS_TOKEN = 'test-metrics-token';
    const response = await router.request('/', { headers: { authorization: 'Bearer test-metrics-token' } });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.users).toBeNull();
    expect(body.accounts.total).toBe(accounts.length);
  } finally {
    if (savedToken === undefined) delete process.env.INTERNAL_METRICS_TOKEN;
    else process.env.INTERNAL_METRICS_TOKEN = savedToken;
  }
});
