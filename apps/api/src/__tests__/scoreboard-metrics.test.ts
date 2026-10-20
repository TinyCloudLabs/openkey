import { afterEach, beforeEach, expect, test } from 'bun:test';
import { mockModules } from './mock-module';

await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({ $queryRaw: async () => [] }) }),
});

const { countAppUsers, countProtocolUsers, exclusionsFromEnv, fetchNodeOwners, qaAccountIds, resetScoreboardRateLimitForTests, scoreboardExclusions, scoreboardMetricsRouter } = await import(
  '../routes/scoreboard-metrics?tc1483' as string
);

type Row = { userId: string; createdAt?: Date; day?: Date; clientId?: string };

// Evaluates the subset of the Prisma where-clauses the metrics code issues.
function table(rows: Row[]) {
  return {
    async findMany({ where }: { where: any }) {
      const seen = new Set<string>();
      for (const row of rows) {
        if (where.userId?.notIn?.includes(row.userId)) continue;
        if (row.clientId !== undefined && where.clientId?.notIn?.includes(row.clientId)) continue;
        if (where.createdAt && !(row.createdAt! >= where.createdAt.gte)) continue;
        if (where.day && !(row.day! >= where.day.gte)) continue;
        seen.add(row.userId);
      }
      return [...seen].map((userId) => ({ userId }));
    },
  };
}

const now = new Date('2026-10-19T12:00:00Z');
const daysAgo = (n: number) => new Date(now.getTime() - n * 86_400_000);
const none = { userIds: new Set<string>(), clientIds: new Set<string>() };

function database(
  parts: Partial<Record<'access' | 'refresh' | 'consent' | 'signIn', Row[]>>,
  keyRows: Array<{ userId: string; address: string }> = [],
  users: Array<{ id: string; email: string }> = [],
) {
  return {
    async $queryRaw(query: TemplateStringsArray, ...values: unknown[]) {
      if (query.join('').includes('"User"')) {
        const domains = new Set(values[0] as string[]);
        return users.filter((u) => domains.has(u.email.split('@')[1] ?? ''));
      }
      const wanted = new Set(values[0] as string[]);
      return keyRows.filter((k) => wanted.has(k.address.toLowerCase())).map((k) => ({ userId: k.userId }));
    },
    oauthAccessToken: table(parts.access ?? []),
    oauthRefreshToken: table(parts.refresh ?? []),
    oauthConsent: table(parts.consent ?? []),
    appSignInDay: table(parts.signIn ?? []),
  };
}

test('protocol users: distinct accounts across keys and address casing, excluded accounts removed', async () => {
  const keys = [
    { userId: 'u1', address: '0xAbCdEf0000000000000000000000000000000001' },
    { userId: 'u1', address: '0x0000000000000000000000000000000000000002' }, // second key, same account
    { userId: 'u2', address: '0x0000000000000000000000000000000000000003' },
    { userId: 'team', address: '0x0000000000000000000000000000000000000004' },
    { userId: 'u9', address: '0x0000000000000000000000000000000000000009' }, // not in the node list
  ];
  const addresses = [
    '0xabcdef0000000000000000000000000000000001',
    '0x0000000000000000000000000000000000000002',
    '0x0000000000000000000000000000000000000003',
    '0x0000000000000000000000000000000000000004',
    '0x00000000000000000000000000000000000000ff', // owner with no OpenKey account
  ];
  const db = database({}, keys);
  expect(await countProtocolUsers(db as any, addresses, none)).toBe(3);
  expect(await countProtocolUsers(db as any, addresses, { ...none, userIds: new Set(['team']) })).toBe(2);
  expect(await countProtocolUsers(db as any, [], none)).toBe(0);
});

test('app users: union across OAuth tokens, consents and sign-in rows, deduplicated, with 7-day activity', async () => {
  const db = database({
    access: [{ userId: 'a', clientId: 'c1', createdAt: daysAgo(1) }, { userId: 'b', clientId: 'c1', createdAt: daysAgo(30) }],
    refresh: [{ userId: 'a', clientId: 'c1', createdAt: daysAgo(2) }],
    consent: [{ userId: 'c', clientId: 'c1', createdAt: daysAgo(40) }],
    signIn: [{ userId: 'd', day: daysAgo(3) }, { userId: 'a', day: daysAgo(3) }, { userId: 'e', day: daysAgo(20) }],
  });
  expect(await countAppUsers(db as any, none, now)).toEqual({ total: 5, active7d: 2 });
});

test('app users: excluded accounts and excluded OAuth clients are removed', async () => {
  const db = database({
    access: [{ userId: 'a', clientId: 'qa-client', createdAt: daysAgo(1) }, { userId: 'b', clientId: 'real', createdAt: daysAgo(1) }],
    signIn: [{ userId: 'team', day: daysAgo(1) }, { userId: 'f', day: daysAgo(1) }],
  });
  const result = await countAppUsers(db as any, { userIds: new Set(['team']), clientIds: new Set(['qa-client']) }, now);
  expect(result).toEqual({ total: 2, active7d: 2 });
});

test('exclusion lists come from config', () => {
  const { userIds, clientIds } = exclusionsFromEnv({ SCOREBOARD_EXCLUDE_USER_IDS: ' a, b ,,', SCOREBOARD_EXCLUDE_CLIENT_IDS: 'c' });
  expect([...userIds]).toEqual(['a', 'b']);
  expect([...clientIds]).toEqual(['c']);
});

test('the test-account registry adds to env exclusions, trimmed and deduped', () => {
  const registry = { userIds: ['c', ' a ', ''], clientIds: ['z'] };
  const { userIds, clientIds } = scoreboardExclusions({ SCOREBOARD_EXCLUDE_USER_IDS: 'a, b' }, registry);
  expect([...userIds].sort()).toEqual(['a', 'b', 'c']);
  expect([...clientIds]).toEqual(['z']);
});

test('QA-eligible accounts are found by email pattern within the registry domains; lookalike and ineligible addresses are not', async () => {
  const registry = { emailDomains: ['example.test'], qaEligiblePatterns: [/^fixture-qa-[a-z0-9]+@example\.test$/] };
  const users = [
    { id: 'qa1', email: 'fixture-qa-7f3a@example.test' },
    { id: 'qa2', email: 'fixture-qa-0123@example.test' },
    { id: 'real', email: 'someone@example.test' },
    { id: 'lookalike', email: 'fixture-qa-7f3a@example.com' },
    { id: 'pending', email: 'fixture-qaabc@example.test' },
  ];
  const ids = await qaAccountIds(database({}, [], users) as unknown as Parameters<typeof qaAccountIds>[0], registry);
  expect(ids).toEqual(['qa1', 'qa2']);
});

test('no registry domains means no QA exclusions, whatever the patterns', async () => {
  const users = [{ id: 'qa1', email: 'fixture-qa-7f3a@example.test' }];
  const registry = { emailDomains: [], qaEligiblePatterns: [/^fixture-qa-[a-z0-9]+@example\.test$/] };
  expect(await qaAccountIds(database({}, [], users) as unknown as Parameters<typeof qaAccountIds>[0], registry)).toEqual([]);
});

const envKeys = ['OPENKEY_METRICS_READ_TOKEN', 'INTERNAL_METRICS_TOKEN', 'NODE_STATS_URL', 'NODE_STATS_READ_TOKEN'] as const;
const savedEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));
const realFetch = globalThis.fetch;
beforeEach(() => {
  process.env.OPENKEY_METRICS_READ_TOKEN = 'read-token';
  process.env.NODE_STATS_URL = 'https://node.example/admin/stats';
  process.env.NODE_STATS_READ_TOKEN = 'node-token';
  resetScoreboardRateLimitForTests();
});
afterEach(() => {
  for (const key of envKeys) {
    if (savedEnv[key] === undefined) delete process.env[key]; else process.env[key] = savedEnv[key];
  }
  globalThis.fetch = realFetch;
});

const getProtocolUsers = () => scoreboardMetricsRouter.request('/protocol-users', { headers: { Authorization: 'Bearer read-token' } });
const stubNode = (respond: (url: string, init: RequestInit) => Response | Promise<Response>) => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  globalThis.fetch = (async (url: string, init: RequestInit) => { calls.push({ url, init }); return respond(url, init); }) as unknown as typeof fetch;
  return calls;
};

test('the endpoints refuse without the read token, with a wrong token, or when unconfigured', async () => {
  const request = (path: string, init: RequestInit) => scoreboardMetricsRouter.request(path, init);
  for (const path of ['/protocol-users', '/app-users']) {
    expect((await request(path, {})).status).toBe(401);
    expect((await request(path, { headers: { Authorization: 'Bearer wrong-token' } })).status).toBe(401);
    expect((await request(path, { headers: { Authorization: 'Basic read-token' } })).status).toBe(401);
  }
  // The general internal-metrics token is not accepted here.
  process.env.INTERNAL_METRICS_TOKEN = 'internal-token';
  expect((await request('/app-users', { headers: { Authorization: 'Bearer internal-token' } })).status).toBe(401);
  delete process.env.OPENKEY_METRICS_READ_TOKEN;
  expect((await request('/app-users', { headers: { Authorization: 'Bearer read-token' } })).status).toBe(503);
});

test('protocol-users takes no input: POST is gone and a query or body cannot supply addresses', async () => {
  const calls = stubNode(() => Response.json({ owners: [] }));
  const post = await scoreboardMetricsRouter.request('/protocol-users', {
    method: 'POST', headers: { Authorization: 'Bearer read-token' }, body: JSON.stringify({ addresses: ['0x0000000000000000000000000000000000000001'] }),
  });
  expect(post.status).toBe(404);
  expect(calls).toHaveLength(0);
});

test('protocol-users fetches owners from the node with the stats token and returns only {count}', async () => {
  const calls = stubNode(() => Response.json({ owners: ['0x0000000000000000000000000000000000000001'] }));
  const res = await getProtocolUsers();
  expect(res.status).toBe(200);
  expect(await res.json()).toEqual({ count: 0 }); // database client is the empty mock: no accounts match
  expect(calls).toHaveLength(1);
  expect(calls[0]!.url).toBe('https://node.example/admin/stats');
  expect((calls[0]!.init.headers as Record<string, string>).Authorization).toBe('Bearer node-token');
});

test('protocol-users answers 503, never a partial count, when the node is unset, errors, or returns a bad body', async () => {
  stubNode(() => new Response('boom', { status: 500 }));
  expect((await getProtocolUsers()).status).toBe(503);
  stubNode(() => Response.json({ owners: ['0x0000000000000000000000000000000000000001', 'nope'] }));
  expect((await getProtocolUsers()).status).toBe(503);
  stubNode(() => Response.json({ other: [] }));
  expect((await getProtocolUsers()).status).toBe(503);
  stubNode(() => { throw new Error('network'); });
  expect((await getProtocolUsers()).status).toBe(503);
  const calls = stubNode(() => Response.json({ owners: [] }));
  delete process.env.NODE_STATS_URL;
  expect((await getProtocolUsers()).status).toBe(503);
  process.env.NODE_STATS_URL = 'https://node.example/admin/stats';
  delete process.env.NODE_STATS_READ_TOKEN;
  expect((await getProtocolUsers()).status).toBe(503);
  expect(calls).toHaveLength(0);
});

test('fetchNodeOwners rejects an oversized owner list', async () => {
  const owners = Array.from({ length: 200_001 }, () => '0x0000000000000000000000000000000000000001');
  const env = { NODE_STATS_URL: 'https://node.example/admin/stats', NODE_STATS_READ_TOKEN: 't' };
  await expect(fetchNodeOwners(env, (async () => Response.json({ owners })) as unknown as typeof fetch)).rejects.toThrow();
});

const nodeEnv = { NODE_STATS_URL: 'https://node.example/admin/stats', NODE_STATS_READ_TOKEN: 't' };

test('fetchNodeOwners rejects an oversize Content-Length without reading the body', async () => {
  const f = (async () => new Response('{"owners":[]}', { headers: { 'content-length': String(17 * 1024 * 1024) } })) as unknown as typeof fetch;
  await expect(fetchNodeOwners(nodeEnv, f)).rejects.toThrow('too large');
});

test('fetchNodeOwners aborts an oversize streamed body without Content-Length', async () => {
  let pulled = 0;
  const chunk = new Uint8Array(1024 * 1024);
  const stream = new ReadableStream<Uint8Array>({ pull(c) { pulled += 1; c.enqueue(chunk); } });
  const f = (async () => new Response(stream)) as unknown as typeof fetch;
  await expect(fetchNodeOwners(nodeEnv, f)).rejects.toThrow('too large');
  expect(pulled).toBeLessThan(25);
});

test('fetchNodeOwners sends identity encoding, disables decompression, and rejects encoded responses unread', async () => {
  let init: RequestInit & { decompress?: boolean } = {};
  let pulled = false;
  const stream = new ReadableStream<Uint8Array>({ pull(ctrl) { pulled = true; ctrl.enqueue(new Uint8Array(8)); ctrl.close(); } }, { highWaterMark: 0 });
  const f = (async (_u: string, i: RequestInit) => { init = i; return new Response(stream, { headers: { 'content-encoding': 'gzip' } }); }) as unknown as typeof fetch;
  await expect(fetchNodeOwners(nodeEnv, f)).rejects.toThrow('encoded');
  expect(pulled).toBe(false);
  expect(init.decompress).toBe(false);
  expect((init.headers as Record<string, string>)['Accept-Encoding']).toBe('identity');
  const ok = (async () => new Response('{"owners":[]}', { headers: { 'content-encoding': 'identity' } })) as unknown as typeof fetch;
  await expect(fetchNodeOwners(nodeEnv, ok)).resolves.toEqual([]);
});

test('fetchNodeOwners single-flights concurrent calls', async () => {
  let n = 0;
  const f = (async () => { n += 1; await new Promise((r) => setTimeout(r, 20)); return Response.json({ owners: [] }); }) as unknown as typeof fetch;
  await Promise.all([fetchNodeOwners(nodeEnv, f), fetchNodeOwners(nodeEnv, f), fetchNodeOwners(nodeEnv, f)]);
  expect(n).toBe(1);
});

test('fetchNodeOwners requires https, allowing http localhost only in development', async () => {
  const f = (async () => Response.json({ owners: [] })) as unknown as typeof fetch;
  const http = { ...nodeEnv, NODE_STATS_URL: 'http://localhost:8000/admin/stats' };
  await expect(fetchNodeOwners({ ...http, NODE_ENV: 'production' }, f)).rejects.toThrow('https');
  await expect(fetchNodeOwners({ ...nodeEnv, NODE_STATS_URL: 'http://node.example/x', NODE_ENV: 'development' }, f)).rejects.toThrow('https');
  await expect(fetchNodeOwners({ ...http, NODE_ENV: 'development' }, f)).resolves.toEqual([]);
});

test('protocol-users is capped at 30 calls a minute per process (429), and each call is audit-logged without addresses', async () => {
  stubNode(() => Response.json({ owners: ['0x00000000000000000000000000000000000000aa'] }));
  const lines: string[] = [];
  const write = process.stdout.write;
  process.stdout.write = ((chunk: string | Uint8Array) => { lines.push(String(chunk)); return true; }) as typeof process.stdout.write;
  const statuses: number[] = [];
  try {
    for (let i = 0; i < 32; i++) statuses.push((await getProtocolUsers()).status);
  } finally {
    process.stdout.write = write;
  }
  expect(statuses.slice(0, 30).every((s) => s === 200)).toBe(true);
  expect(statuses.slice(30)).toEqual([429, 429]);
  const audit = lines.filter((l) => l.includes('scoreboard_protocol_users_call')).map((l) => JSON.parse(l));
  expect(audit).toHaveLength(32);
  expect(audit[0]).toMatchObject({ status: 200, count: 0 });
  expect(audit[31]).toMatchObject({ status: 429 });
  expect(lines.join('')).not.toContain('00000000000000000000000000000000000000aa');
  expect(lines.join('')).not.toContain('read-token');
});
