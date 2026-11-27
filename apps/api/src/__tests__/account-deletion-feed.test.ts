import { afterEach, beforeEach, expect, test } from 'bun:test';
import { mockModules } from './mock-module';

type Row = { id: bigint; addresses: string[]; deletedAt: Date };
const rows: Row[] = [];
const queries: Array<{ gt: bigint; take: number }> = [];
let failReads = false;
// The route captures this client when it loads.
const routeDatabase = {
  accountDeletionEvent: {
    async findMany({ where, orderBy, take }: { where: { id: { gt: bigint } }; orderBy: { id: 'asc' }; take: number }) {
      if (failReads) throw new Error('database unavailable');
      expect(orderBy).toEqual({ id: 'asc' });
      queries.push({ gt: where.id.gt, take });
      return rows.filter((row) => row.id > where.id.gt).sort((a, b) => (a.id < b.id ? -1 : 1)).slice(0, take);
    },
  },
};
await mockModules({ '@openkey/db': () => ({ createPrismaClient: () => routeDatabase }) });
const { accountDeletionFeedRouter } = await import('../routes/account-deletion-feed?tc4416' as string);

// Built at runtime: a fixed credential-shaped literal does not belong in a fixture.
const BEARER = 'tb' + 'ab'.repeat(16); // 34 characters: the feed needs at least 32
const ENVIRONMENT = 'https://api.openkey.test';
const envKeys = ['OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN', 'BETTER_AUTH_URL'] as const;
const savedEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));
beforeEach(() => {
  process.env.OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN = BEARER;
  process.env.BETTER_AUTH_URL = `${ENVIRONMENT}/`;
  rows.length = 0;
  queries.length = 0;
  failReads = false;
});
afterEach(() => {
  for (const key of envKeys) {
    if (savedEnv[key] === undefined) delete process.env[key]; else process.env[key] = savedEnv[key];
  }
});

const address = (n: number) => `0x${n.toString(16).padStart(40, '0')}`;
const seed = (count: number, firstId = 1n) => {
  for (let i = 0; i < count; i++) rows.push({ id: firstId + BigInt(i), addresses: [address(i + 1), address(i + 1000)], deletedAt: new Date(Date.UTC(2026, 10, 1, 0, 0, i)) });
};
const get = (query = '', headers: Record<string, string> = { Authorization: `Bearer ${BEARER}` }) =>
  accountDeletionFeedRouter.request(`/${query}`, { headers });

test('503 with no body while the token is unset or empty; 401 for a missing or wrong bearer; 200 for the right one', async () => {
  for (const unset of [undefined, '']) {
    if (unset === undefined) delete process.env.OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN; else process.env.OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN = unset;
    const response = await get();
    expect(response.status).toBe(503);
    expect(await response.text()).toBe('');
    expect(response.headers.get('cache-control')).toBe('no-store');
    // A request that carries the empty token is not authorised either.
    expect((await get('', { Authorization: 'Bearer ' })).status).toBe(503);
  }
  process.env.OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN = BEARER;
  expect((await get('', {})).status).toBe(401);
  expect((await get('', { Authorization: BEARER })).status).toBe(401);
  expect((await get('', { Authorization: `Bearer ${BEARER}x` })).status).toBe(401);
  expect((await get('', { Authorization: `Bearer ${BEARER.slice(0, -1)}` })).status).toBe(401);
  expect((await get('', { Authorization: `Bearer ${'tb' + 'cd'.repeat(16)}` })).status).toBe(401);
  for (const refused of [await get('', {}), await get('', { Authorization: 'Bearer nope' })]) {
    expect(refused.headers.get('cache-control')).toBe('no-store');
    expect(await refused.json()).toEqual({ error: 'Unauthorized' });
  }
  expect((await get()).status).toBe(200);
  expect(queries).toHaveLength(1);
});

test('every response names the environment: empty pages, full pages, and the answer to a bad request', async () => {
  const empty = await get();
  expect(empty.status).toBe(200);
  expect(await empty.json()).toEqual({ environment: ENVIRONMENT, events: [], next: '0' });
  seed(2);
  const full = await (await get('?after=0')).json() as { environment: string };
  expect(full.environment).toBe(ENVIRONMENT);
  process.env.BETTER_AUTH_URL = 'https://api.staging.example.test';
  expect(((await (await get()).json()) as { environment: string }).environment).toBe('https://api.staging.example.test');
  // No configured environment: the feed does not answer without naming one.
  delete process.env.BETTER_AUTH_URL;
  const unnamed = await get();
  expect(unnamed.status).toBe(503);
  expect(await unnamed.text()).toBe('');
});

test('pages by id: page size, `next` is the last id, an empty page returns the `after` it was given', async () => {
  seed(5);
  const first = await (await get('?limit=2')).json() as { events: Array<{ id: string }>; next: string };
  expect(first.events.map((event) => event.id)).toEqual(['1', '2']);
  expect(first.next).toBe('2');
  const second = await (await get(`?after=${first.next}&limit=2`)).json() as { events: Array<{ id: string }>; next: string };
  expect(second.events.map((event) => event.id)).toEqual(['3', '4']);
  const third = await (await get(`?after=${second.next}&limit=2`)).json() as { events: Array<{ id: string }>; next: string };
  expect(third.events.map((event) => event.id)).toEqual(['5']);
  expect(third.next).toBe('5');
  const done = await (await get(`?after=${third.next}&limit=2`)).json();
  expect(done).toEqual({ environment: ENVIRONMENT, events: [], next: '5' });
  expect(((await (await get('?after=0042')).json()) as { next: string }).next).toBe('42');
});

test('events carry exactly id, addresses and deletedAt; ids are strings and keep 64-bit precision', async () => {
  const big = 9_007_199_254_740_993n; // beyond Number.MAX_SAFE_INTEGER
  rows.push({ id: big, addresses: ['0xAbCdEf0123456789aBcDeF0123456789AbCdEf01', address(7)], deletedAt: new Date('2026-11-01T00:00:00.123Z') });
  const page = await (await get(`?after=${big - 1n}`)).json() as { events: Array<Record<string, unknown>>; next: string };
  expect(page.events).toEqual([{ id: '9007199254740993', addresses: ['0xAbCdEf0123456789aBcDeF0123456789AbCdEf01', address(7)], deletedAt: '2026-11-01T00:00:00.123Z' }]);
  expect(Object.keys(page.events[0]!)).toEqual(['id', 'addresses', 'deletedAt']);
  expect(Object.keys(page)).toEqual(['environment', 'events', 'next']);
  expect(page.next).toBe('9007199254740993');
  expect(queries.at(-1)!.gt).toBe(big - 1n);
});

test('limit defaults to 100 and is clamped to 100', async () => {
  seed(130);
  expect(((await (await get()).json()) as { events: unknown[] }).events).toHaveLength(100);
  expect(((await (await get('?limit=100')).json()) as { events: unknown[] }).events).toHaveLength(100);
  expect(((await (await get('?limit=5000')).json()) as { events: unknown[] }).events).toHaveLength(100);
  expect(queries.map((query) => query.take)).toEqual([100, 100, 100]);
  expect(((await (await get('?limit=1')).json()) as { events: unknown[] }).events).toHaveLength(1);
});

test('400 for a bad after or limit, with the environment unnamed and nothing read', async () => {
  seed(3);
  const bad = ['after=-1', 'after=abc', 'after=', 'after=1.5', 'after=1e3', 'after=0x10', 'after=+1', 'after=%201', 'after=9223372036854775808',
    'after=1&after=2', 'limit=0', 'limit=-5', 'limit=abc', 'limit=', 'limit=1.5', 'limit=1e2', 'limit=1&limit=2'];
  for (const query of bad) {
    const response = await get(`?${query}`);
    expect(response.status, query).toBe(400);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toEqual({ error: 'Invalid after or limit parameter' });
  }
  expect(queries).toEqual([]);
  expect((await get('?after=9223372036854775807')).status).toBe(200);
});

test('responses are never cached', async () => {
  seed(1);
  for (const response of [await get(), await get('?after=x'), await get('', {}), await accountDeletionFeedRouter.request('/', { method: 'POST' })]) {
    expect(response.headers.get('cache-control')).toBe('no-store');
  }
});

test('only GET is served: every other method is refused before auth, reads nothing and writes nothing', async () => {
  seed(2);
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    const response = await accountDeletionFeedRouter.request('/', { method, headers: { Authorization: `Bearer ${BEARER}` }, body: '{}' });
    expect(response.status, method).toBe(405);
    expect(response.headers.get('allow')).toBe('GET');
  }
  expect(queries).toEqual([]);
  expect(rows).toHaveLength(2);
  expect(Object.keys(routeDatabase.accountDeletionEvent)).toEqual(['findMany']);
});

test('a database failure answers 503 with no detail', async () => {
  failReads = true;
  const response = await get();
  expect(response.status).toBe(503);
  expect(await response.text()).toBe('');
  expect(response.headers.get('cache-control')).toBe('no-store');
});

test('the log carries counts only: no address, bearer or Authorization header', async () => {
  seed(2);
  const lines: string[] = [];
  const originalWrite = process.stdout.write;
  process.stdout.write = ((chunk: unknown) => { lines.push(String(chunk)); return true; }) as typeof process.stdout.write;
  try {
    await get();
    await get('', { Authorization: 'Bearer wrong' });
    failReads = true;
    await get();
  } finally {
    process.stdout.write = originalWrite;
  }
  const output = lines.join('');
  expect(output).toContain('account_deletion_feed_call');
  expect(output).not.toContain(BEARER);
  expect(output).not.toContain('Bearer');
  expect(output).not.toMatch(/0x[0-9a-f]{40}/i);
});

test('a token shorter than 32 characters is not served, even with the matching bearer; 32 characters is', async () => {
  seed(1);
  const token = (length: number) => 'tb'.padEnd(length, 'ab');
  const short = token(31);
  expect(short).toHaveLength(31);
  process.env.OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN = short;
  const refused = await get('', { Authorization: `Bearer ${short}` });
  expect(refused.status).toBe(503);
  expect(await refused.text()).toBe('');
  expect(refused.headers.get('cache-control')).toBe('no-store');
  expect(queries).toEqual([]);
  const enough = token(32);
  expect(enough).toHaveLength(32);
  process.env.OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN = enough;
  const served = await get('', { Authorization: `Bearer ${enough}` });
  expect(served.status).toBe(200);
  expect(((await served.json()) as { events: unknown[] }).events).toHaveLength(1);
});
