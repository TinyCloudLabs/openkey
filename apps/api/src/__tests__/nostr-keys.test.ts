import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { verifyEvent, type Event as NostrToolsEvent } from 'nostr-tools/pure';

process.env.DEV_SEALING_KEY = 'test-sealing-key-for-nostr-route-tests';

const user = { id: 'user_1', email: 'test@example.com' };
const otherUser = { id: 'user_2', email: 'other@example.com' };

type Row = Record<string, any>;

function matchesWhere(row: Row, where: Row): boolean {
  return Object.entries(where).every(([field, cond]) => {
    const value = row[field];
    if (cond === null) return value === null || value === undefined;
    if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
      if ('gt' in cond) return value instanceof Date && value.getTime() > (cond.gt as Date).getTime();
      if ('has' in cond) return Array.isArray(value) && value.includes(cond.has);
      if ('not' in cond) return value !== cond.not;
    }
    return value === cond;
  });
}

function applySelect(row: Row, select?: Row): Row {
  if (!select) return row;
  const out: Row = {};
  for (const field of Object.keys(select)) {
    if (select[field]) out[field] = row[field];
  }
  return out;
}

function makeTable(rows: Row[]) {
  return {
    findFirst: mock(async ({ where, select, orderBy }: { where: Row; select?: Row; orderBy?: Row }) => {
      let matches = rows.filter((r) => matchesWhere(r, where));
      if (orderBy) {
        const [field, dir] = Object.entries(orderBy)[0] as [string, 'asc' | 'desc'];
        matches = [...matches].sort((a, b) => (dir === 'desc' ? b[field] - a[field] : a[field] - b[field]));
      }
      const row = matches[0];
      return row ? applySelect(row, select) : null;
    }),
    findMany: mock(async ({ where, select }: { where: Row; select?: Row }) =>
      rows.filter((r) => matchesWhere(r, where)).map((r) => applySelect(r, select)),
    ),
    create: mock(async ({ data, select }: { data: Row; select?: Row }) => {
      const row = { id: data.id ?? `id_${rows.length + 1}`, createdAt: new Date(), ...data };
      rows.push(row);
      return applySelect(row, select);
    }),
    updateMany: mock(async ({ where, data }: { where: Row; data: Row }) => {
      const matched = rows.filter((r) => matchesWhere(r, where));
      for (const r of matched) Object.assign(r, data);
      return { count: matched.length };
    }),
    _rows: rows,
  };
}

// These arrays and the `prisma` object below are created exactly once: the
// mocked `@openkey/tee`/`@openkey/db` modules are only evaluated on the
// route module's first dynamic import (ESM module cache), so tests reset
// state in place (array mutation) rather than by rebinding `prisma`.
const nostrKeyRows: Row[] = [];
const grantRows: Row[] = [];
const decisionRows: Row[] = [];

const prisma = {
  nostrKey: makeTable(nostrKeyRows),
  nostrSigningGrant: makeTable(grantRows),
  nostrSigningDecision: makeTable(decisionRows),
};

mock.module('@openkey/db', () => ({
  createPrismaClient: () => prisma,
}));

let currentUser = user;
mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', currentUser);
    c.set('session', { id: 'session_1', userId: currentUser.id, expiresAt: new Date(Date.now() + 60_000) });
    await next();
  }),
}));

beforeEach(() => {
  nostrKeyRows.length = 0;
  grantRows.length = 0;
  decisionRows.length = 0;
  currentUser = user;
});

async function router() {
  return (await import('../routes/nostr-keys')).nostrKeysRouter;
}

async function createKey() {
  const r = await router();
  const res = await r.request('/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  expect(res.status).toBe(201);
  return (await res.json()).key as { id: string; pubkeyHex: string; npub: string };
}

async function grant(r: Awaited<ReturnType<typeof router>>, keyId: string, body: Record<string, unknown>) {
  return r.request(`/${keyId}/grants`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('POST /api/keys/nostr - generate', () => {
  test('generates a real BIP-340 keypair and returns only public metadata', async () => {
    const r = await router();
    const res = await r.request('/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.key.pubkeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(body.key.npub).toMatch(/^npub1/);
    expect(body.key.sealedSecret).toBeUndefined();
    expect(nostrKeyRows[0]!.sealedSecret).toBeTruthy();
  });

  test('is idempotent: a second call returns the same key', async () => {
    const first = await createKey();
    const r = await router();
    const res = await r.request('/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    const body = await res.json();
    expect(body.key.id).toBe(first.id);
    expect(nostrKeyRows).toHaveLength(1);
  });
});

describe('sign-event grant enforcement', () => {
  test('kind not granted is rejected with interaction_required', async () => {
    const key = await createKey();
    const r = await router();
    const res = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientOrigin: 'http://localhost:3000',
        event: { pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000), kind: 9, tags: [['h', 'dev']], content: 'hi' },
      }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe('interaction_required');
    expect(decisionRows.at(-1)).toMatchObject({ allowed: false, reasonCode: 'interaction_required' });
  });

  test('silent sign succeeds with a valid grant and returns an independently verifiable event', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [9] });

    const unsignedEvent = {
      pubkey: key.pubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 9,
      tags: [['h', 'dev']],
      content: 'hello channel',
    };
    const res = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientOrigin: 'http://localhost:3000', event: unsignedEvent }),
    });
    expect(res.status).toBe(200);
    const { event } = await res.json();
    expect(event.kind).toBe(9);
    expect(event.content).toBe('hello channel');
    expect(event.tags).toEqual([['h', 'dev']]);
    expect(verifyEvent(event as NostrToolsEvent)).toBe(true);
  });

  test('kind 22242 requires exactly one relay + challenge tag matching the granted relayUrl', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [22242], relayUrl: 'ws://localhost:8080' });

    const goodEvent = {
      pubkey: key.pubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 22242,
      tags: [['relay', 'ws://localhost:8080'], ['challenge', 'abc']],
      content: '',
    };
    const ok = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientOrigin: 'http://localhost:3000', event: goodEvent }),
    });
    expect(ok.status).toBe(200);

    const wrongRelay = { ...goodEvent, tags: [['relay', 'ws://evil.example.com'], ['challenge', 'abc']] };
    const bad = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientOrigin: 'http://localhost:3000', event: wrongRelay }),
    });
    expect(bad.status).toBe(403);
  });

  test('expired grant is rejected', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [9], ttlSeconds: 1 });
    grantRows[0]!.expiresAt = new Date(Date.now() - 1000);

    const res = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientOrigin: 'http://localhost:3000',
        event: { pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000), kind: 9, tags: [], content: 'x' },
      }),
    });
    expect(res.status).toBe(403);
  });

  test('revoked grant makes the very next sign fail closed', async () => {
    const key = await createKey();
    const r = await router();
    const grantRes = await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [9] });
    const { grant: g } = await grantRes.json();

    const event = { pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000), kind: 9, tags: [], content: 'x' };
    const before = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientOrigin: 'http://localhost:3000', event }),
    });
    expect(before.status).toBe(200);

    const revokeRes = await r.request(`/grants/${g.id}`, { method: 'DELETE' });
    expect(revokeRes.status).toBe(200);

    const after = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientOrigin: 'http://localhost:3000', event: { ...event, created_at: Math.floor(Date.now() / 1000) } }),
    });
    expect(after.status).toBe(403);
  });

  test('a grant for one client origin does not authorize a different origin', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [9] });

    const res = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientOrigin: 'http://evil.example.com',
        event: { pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000), kind: 9, tags: [], content: 'x' },
      }),
    });
    expect(res.status).toBe(403);
  });

  test('unsupported kind is rejected outright, never just ungranted', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [9] });
    const res = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientOrigin: 'http://localhost:3000',
        event: { pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000), kind: 0, tags: [], content: 'x' },
      }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('kind_not_supported');
  });

  test('another user cannot sign with someone else\'s key', async () => {
    const key = await createKey();
    currentUser = otherUser;
    const r = await router();
    const res = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientOrigin: 'http://localhost:3000',
        event: { pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000), kind: 9, tags: [], content: 'x' },
      }),
    });
    expect(res.status).toBe(404);
  });

  test('rejects a wildcard or malformed clientOrigin on grant creation', async () => {
    const key = await createKey();
    const r = await router();
    const res = await grant(r, key.id, { clientOrigin: '*', kinds: [9] });
    expect(res.status).toBe(400);
  });

  test('timestamp far outside the skew window is rejected', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [9] });
    const res = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientOrigin: 'http://localhost:3000',
        event: { pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000) - 10_000, kind: 9, tags: [], content: 'x' },
      }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('timestamp_out_of_window');
  });
});
