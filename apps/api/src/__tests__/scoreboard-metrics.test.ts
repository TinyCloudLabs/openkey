import { afterEach, beforeEach, expect, test } from 'bun:test';
import { mockModules } from './mock-module';

await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({}) }),
});

const { countAppUsers, countProtocolUsers, exclusionsFromEnv, scoreboardMetricsRouter } = await import(
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

function database(parts: Partial<Record<'access' | 'refresh' | 'consent' | 'signIn', Row[]>>, keyRows: Array<{ userId: string; address: string }> = []) {
  return {
    async $queryRaw(_q: TemplateStringsArray, ...values: unknown[]) {
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

const saved = process.env.OPENKEY_METRICS_READ_TOKEN;
const savedInternal = process.env.INTERNAL_METRICS_TOKEN;
beforeEach(() => { process.env.OPENKEY_METRICS_READ_TOKEN = 'read-token'; });
afterEach(() => {
  if (saved === undefined) delete process.env.OPENKEY_METRICS_READ_TOKEN; else process.env.OPENKEY_METRICS_READ_TOKEN = saved;
  if (savedInternal === undefined) delete process.env.INTERNAL_METRICS_TOKEN; else process.env.INTERNAL_METRICS_TOKEN = savedInternal;
});

test('the endpoints refuse without the read token, with a wrong token, or when unconfigured', async () => {
  const request = (path: string, init: RequestInit) => scoreboardMetricsRouter.request(path, init);
  const body = JSON.stringify({ addresses: [] });
  for (const [path, method] of [['/protocol-users', 'POST'], ['/app-users', 'GET']] as const) {
    expect((await request(path, { method, body: method === 'POST' ? body : undefined })).status).toBe(401);
    expect((await request(path, { method, headers: { Authorization: 'Bearer wrong-token' }, body: method === 'POST' ? body : undefined })).status).toBe(401);
    expect((await request(path, { method, headers: { Authorization: 'Basic read-token' }, body: method === 'POST' ? body : undefined })).status).toBe(401);
  }
  // The general internal-metrics token is not accepted here.
  process.env.INTERNAL_METRICS_TOKEN = 'internal-token';
  expect((await request('/app-users', { headers: { Authorization: 'Bearer internal-token' } })).status).toBe(401);
  delete process.env.OPENKEY_METRICS_READ_TOKEN;
  expect((await request('/app-users', { headers: { Authorization: 'Bearer read-token' } })).status).toBe(503);
});

test('protocol-users rejects malformed bodies and returns only a count shape', async () => {
  const post = (body: unknown) => scoreboardMetricsRouter.request('/protocol-users', {
    method: 'POST', headers: { Authorization: 'Bearer read-token' }, body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  expect((await post('not json')).status).toBe(400);
  expect((await post({ addresses: 'nope' })).status).toBe(400);
  expect((await post({ addresses: ['0x123'] })).status).toBe(400);
  const ok = await post({ addresses: [] });
  expect(ok.status).toBe(200);
  expect(await ok.json()).toEqual({ count: 0 });
});
