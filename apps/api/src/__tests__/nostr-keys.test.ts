import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  verifyEvent,
  type Event as NostrToolsEvent,
} from 'nostr-tools/pure';
import { nip44 } from 'nostr-tools';
import * as nip59 from 'nostr-tools/nip59';

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
    upsert: mock(async ({ where, create, update, select }: { where: Row; create: Row; update: Row; select?: Row }) => {
      const existing = rows.find((r) => matchesWhere(r, where));
      if (existing) {
        Object.assign(existing, update);
        return applySelect(existing, select);
      }
      const row = { id: create.id ?? `id_${rows.length + 1}`, createdAt: new Date(), ...create };
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

function postJson(r: Awaited<ReturnType<typeof router>>, path: string, body: Record<string, unknown>) {
  return r.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function postSign(
  r: Awaited<ReturnType<typeof router>>,
  keyId: string,
  event: Record<string, unknown>,
  clientOrigin = 'http://localhost:3000',
) {
  return postJson(r, `/${keyId}/sign-event`, { clientOrigin, event });
}

/**
 * Simulate a revoke race: the grant is revoked immediately after the next
 * grant lookup succeeds, so the route's final pre-release re-check must
 * catch it. Returns a restore function.
 */
function revokeAfterNextGrantLookup(): () => void {
  const table = prisma.nostrSigningGrant as unknown as {
    findFirst: (args: Row) => Promise<Row | null>;
    findMany: (args: Row) => Promise<Row[]>;
  };
  const originalFindFirst = table.findFirst;
  const originalFindMany = table.findMany;
  let raced = false;
  const revokeAll = () => {
    for (const row of grantRows) row.revokedAt = new Date();
  };
  table.findFirst = async (args: Row) => {
    const result = await originalFindFirst(args);
    if (!raced && result) {
      raced = true;
      revokeAll();
    }
    return result;
  };
  table.findMany = async (args: Row) => {
    const result = await originalFindMany(args);
    if (!raced && result.length > 0) {
      raced = true;
      revokeAll();
    }
    return result;
  };
  return () => {
    table.findFirst = originalFindFirst;
    table.findMany = originalFindMany;
  };
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

  test('concurrent first-connect calls resolve to one durable identity', async () => {
    const r = await router();
    const request = () => r.request('/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });

    const [first, second] = await Promise.all([request(), request()]);
    const [firstBody, secondBody] = await Promise.all([first.json(), second.json()]);

    expect(firstBody.key.id).toBe(secondBody.key.id);
    expect(firstBody.key.pubkeyHex).toBe(secondBody.key.pubkeyHex);
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
      tags: [['relay', 'ws://localhost:8080'], ['challenge', 'super-secret-challenge']],
      content: '',
    };
    const ok = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientOrigin: 'http://localhost:3000', event: goodEvent }),
    });
    expect(ok.status).toBe(200);
    expect(decisionRows.at(-1)?.tags).toEqual({ count: 2, names: ['relay', 'challenge'] });
    expect(JSON.stringify(decisionRows.at(-1))).not.toContain('super-secret-challenge');

    const wrongRelay = { ...goodEvent, tags: [['relay', 'ws://evil.example.com'], ['challenge', 'abc']] };
    const bad = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientOrigin: 'http://localhost:3000', event: wrongRelay }),
    });
    expect(bad.status).toBe(403);
  });

  test('grant relay URLs reject credentials and fragments', async () => {
    const key = await createKey();
    const r = await router();
    for (const relayUrl of ['wss://user:secret@relay.example', 'wss://relay.example/#secret']) {
      const res = await grant(r, key.id, {
        clientOrigin: 'http://localhost:3000',
        kinds: [22242],
        relayUrl,
      });
      expect(res.status).toBe(400);
    }
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
    // kind 1 (plain text note) is deliberately outside the Buzz matrix.
    const res = await r.request(`/${key.id}/sign-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientOrigin: 'http://localhost:3000',
        event: { pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000), kind: 1, tags: [], content: 'x' },
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

  test('destination-bound kinds: a grant for one relay never covers another destination', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [24242, 27235], relayUrl: 'ws://localhost:8080' });
    const now = Math.floor(Date.now() / 1000);
    const sha = 'd'.repeat(64);
    const uuid = '01234567-89ab-cdef-0123-456789abcdef';

    const blossom = (server: string) => ({
      pubkey: key.pubkeyHex,
      created_at: now,
      kind: 24242,
      tags: [['t', 'upload'], ['x', sha], ['expiration', String(now + 300)], ['server', server]],
      content: 'Upload buzz-media',
    });
    const okBlossom = await postSign(r, key.id, blossom('localhost:8080'));
    expect(okBlossom.status).toBe(200);
    expect(verifyEvent((await okBlossom.json()).event as NostrToolsEvent)).toBe(true);

    const badBlossom = await postSign(r, key.id, blossom('evil.example.com'));
    expect(badBlossom.status).toBe(403);
    expect((await badBlossom.json()).reason).toBe('destination_not_granted');
    expect(decisionRows.at(-1)).toMatchObject({ allowed: false, reasonCode: 'destination_not_granted' });

    const httpAuth = (u: string) => ({
      pubkey: key.pubkeyHex,
      created_at: now,
      kind: 27235,
      tags: [['u', u], ['method', 'POST'], ['payload', sha], ['nonce', uuid]],
      content: '',
    });
    const okHttp = await postSign(r, key.id, httpAuth('http://localhost:8080/api/invites'));
    expect(okHttp.status).toBe(200);
    const badHttp = await postSign(r, key.id, httpAuth('http://evil.example.com/api/invites'));
    expect(badHttp.status).toBe(403);
    const badPath = await postSign(r, key.id, httpAuth('http://localhost:8080/api/admin'));
    expect(badPath.status).toBe(403);
  });

  test('canonical fixtures for the expanded kinds sign end-to-end under grants', async () => {
    const key = await createKey();
    const r = await router();
    const now = Math.floor(Date.now() / 1000);
    const pk2 = 'b'.repeat(64);
    const id = 'c'.repeat(64);
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [0, 7, 1984, 20001, 40002, 41010, 9030, 9031, 9032, 9040, 9041, 9042, 9043, 9044, 30300] });

    const nip44Payload = (() => {
      const bytes = new Uint8Array(99);
      bytes[0] = 2;
      return Buffer.from(bytes).toString('base64');
    })();

    const fixtures: Array<{ kind: number; tags: string[][]; content: string }> = [
      { kind: 0, tags: [], content: JSON.stringify({ name: 'Ocean' }) },
      { kind: 7, tags: [['e', id], ['h', 'chan']], content: '🔥' },
      { kind: 1984, tags: [['p', pk2], ['e', id, 'spam']], content: 'note' },
      { kind: 20001, tags: [['status', 'online']], content: 'online' },
      { kind: 40002, tags: [['h', 'chan'], ['e', id, '', 'reply']], content: 'hi' },
      { kind: 41010, tags: [['p', pk2]], content: '' },
      { kind: 9030, tags: [['p', pk2], ['role', 'member']], content: '' },
      { kind: 9031, tags: [['p', pk2]], content: '' },
      { kind: 9032, tags: [['p', pk2], ['role', 'owner']], content: '' },
      { kind: 9040, tags: [['p', pk2], ['expiration', String(now + 60)], ['reason', 'spam']], content: '' },
      { kind: 9041, tags: [['p', pk2]], content: '' },
      { kind: 9042, tags: [['p', pk2], ['expiration', String(now + 60)]], content: '' },
      { kind: 9043, tags: [['p', pk2]], content: '' },
      { kind: 9044, tags: [['report', id], ['status', 'resolved'], ['action', 'ban']], content: '' },
      { kind: 30300, tags: [['d', 'e'.repeat(32)], ['not_before', String(now)]], content: nip44Payload },
    ];

    for (const fixture of fixtures) {
      const res = await postSign(r, key.id, { pubkey: key.pubkeyHex, created_at: now, ...fixture });
      expect(res.status).toBe(200);
      const { event } = await res.json();
      expect(event.kind).toBe(fixture.kind);
      expect(event.tags).toEqual(fixture.tags);
      expect(event.content).toBe(fixture.content);
      expect(verifyEvent(event as NostrToolsEvent)).toBe(true);
    }
  });

  test('a granted kind with a malformed Buzz payload is still rejected (policy, not just grants)', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [7, 20001] });
    const now = Math.floor(Date.now() / 1000);

    const badReaction = await postSign(r, key.id, {
      pubkey: key.pubkeyHex, created_at: now, kind: 7, tags: [['e', 'not-hex'], ['h', 'chan']], content: '🔥',
    });
    expect(badReaction.status).toBe(400);
    expect((await badReaction.json()).error).toBe('reaction_tags_invalid');

    const badPresence = await postSign(r, key.id, {
      pubkey: key.pubkeyHex, created_at: now, kind: 20001, tags: [['status', 'online']], content: 'away',
    });
    expect(badPresence.status).toBe(400);
    expect((await badPresence.json()).error).toBe('presence_tags_invalid');
  });

  test('rejects malformed or unbounded tag structures before signing', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [9] });

    const invalidTags = [
      'not-an-array',
      [[]],
      [['h', { nested: 'not a string' }]],
      [['h', ...Array.from({ length: 20 }, (_, i) => `value-${i}`)]],
      [['h', 'x'.repeat(513)]],
    ];

    for (const tags of invalidTags) {
      const res = await r.request(`/${key.id}/sign-event`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          clientOrigin: 'http://localhost:3000',
          event: {
            pubkey: key.pubkeyHex,
            created_at: Math.floor(Date.now() / 1000),
            kind: 9,
            tags,
            content: 'x',
          },
        }),
      });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe('tags_invalid');
    }
  });
});

describe('grant creation - capability model v2', () => {
  test('accepts kinds plus operations and persists both', async () => {
    const key = await createKey();
    const r = await router();
    const res = await grant(r, key.id, {
      clientOrigin: 'http://localhost:3000',
      kinds: [9, 22242],
      operations: ['nip44_encrypt', 'nip59_wrap'],
      relayUrl: 'ws://localhost:8080',
    });
    expect(res.status).toBe(201);
    const { grant: g } = await res.json();
    expect([...g.allowedKinds].sort((a: number, b: number) => a - b)).toEqual([9, 22242]);
    expect(g.allowedOperations.sort()).toEqual(['nip44_encrypt', 'nip59_wrap']);
    expect(g.relayUrl).toBe('ws://localhost:8080');
  });

  test('accepts an operations-only grant', async () => {
    const key = await createKey();
    const r = await router();
    const res = await grant(r, key.id, { clientOrigin: 'http://localhost:3000', operations: ['nip59_unwrap'] });
    expect(res.status).toBe(201);
  });

  test('rejects unknown operations, empty capability sets, and unsupported kinds', async () => {
    const key = await createKey();
    const r = await router();
    expect((await grant(r, key.id, { clientOrigin: 'http://localhost:3000', operations: ['export_secret'] })).status).toBe(400);
    expect((await grant(r, key.id, { clientOrigin: 'http://localhost:3000' })).status).toBe(400);
    expect((await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [], operations: [] })).status).toBe(400);
    expect((await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [1] })).status).toBe(400);
  });

  test('every destination-bound kind requires a relayUrl', async () => {
    const key = await createKey();
    const r = await router();
    for (const kind of [22242, 24242, 27235]) {
      const res = await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [kind] });
      expect(res.status).toBe(400);
      const withRelay = await grant(r, key.id, { clientOrigin: 'http://localhost:3000', kinds: [kind], relayUrl: 'ws://localhost:8080' });
      expect(withRelay.status).toBe(201);
    }
  });
});

describe('NIP-44 custody operations', () => {
  const origin = 'http://localhost:3000';

  test('encrypt requires a grant naming the operation, then round-trips through decrypt', async () => {
    const key = await createKey();
    const r = await router();

    const denied = await postJson(r, `/${key.id}/nip44/encrypt`, {
      clientOrigin: origin, peerPubkey: key.pubkeyHex, plaintext: 'remember me',
    });
    expect(denied.status).toBe(403);
    const deniedBody = await denied.json();
    expect(deniedBody.error).toBe('interaction_required');
    expect(deniedBody.approvalUrl).toContain('operation=nip44_encrypt');
    expect(decisionRows.at(-1)).toMatchObject({ allowed: false, operation: 'nip44_encrypt', reasonCode: 'interaction_required' });

    await grant(r, key.id, { clientOrigin: origin, operations: ['nip44_encrypt', 'nip44_decrypt'] });
    const encrypted = await postJson(r, `/${key.id}/nip44/encrypt`, {
      clientOrigin: origin, peerPubkey: key.pubkeyHex, plaintext: 'remember me',
    });
    expect(encrypted.status).toBe(200);
    const { ciphertext } = await encrypted.json();
    expect(typeof ciphertext).toBe('string');
    expect(ciphertext).not.toContain('remember me');

    const decrypted = await postJson(r, `/${key.id}/nip44/decrypt`, {
      clientOrigin: origin, peerPubkey: key.pubkeyHex, payload: ciphertext,
    });
    expect(decrypted.status).toBe(200);
    expect((await decrypted.json()).plaintext).toBe('remember me');
  });

  test('encrypt refuses non-self peers and unbounded plaintexts', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, operations: ['nip44_encrypt'] });

    const wrongPeer = await postJson(r, `/${key.id}/nip44/encrypt`, {
      clientOrigin: origin, peerPubkey: 'b'.repeat(64), plaintext: 'x',
    });
    expect(wrongPeer.status).toBe(400);
    expect((await wrongPeer.json()).error).toBe('nip44_peer_must_be_self');

    const tooLarge = await postJson(r, `/${key.id}/nip44/encrypt`, {
      clientOrigin: origin, peerPubkey: key.pubkeyHex, plaintext: 'x'.repeat(4097),
    });
    expect(tooLarge.status).toBe(400);
    expect((await tooLarge.json()).error).toBe('nip44_plaintext_invalid');

    const empty = await postJson(r, `/${key.id}/nip44/encrypt`, {
      clientOrigin: origin, peerPubkey: key.pubkeyHex, plaintext: '',
    });
    expect(empty.status).toBe(400);
  });

  test('decrypt handles peer ciphertexts (observer frames) and rejects tampered payloads', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, operations: ['nip44_decrypt'] });

    const peerSecret = generateSecretKey();
    const peerPubkey = getPublicKey(peerSecret);
    const conversationKey = nip44.v2.utils.getConversationKey(peerSecret, key.pubkeyHex);
    const payload = nip44.v2.encrypt('telemetry frame', conversationKey);

    const decrypted = await postJson(r, `/${key.id}/nip44/decrypt`, {
      clientOrigin: origin, peerPubkey, payload,
    });
    expect(decrypted.status).toBe(200);
    expect((await decrypted.json()).plaintext).toBe('telemetry frame');

    const decoded = Buffer.from(payload, 'base64');
    decoded[decoded.length - 1] = decoded[decoded.length - 1]! ^ 0xff;
    const tampered = await postJson(r, `/${key.id}/nip44/decrypt`, {
      clientOrigin: origin, peerPubkey, payload: decoded.toString('base64'),
    });
    expect(tampered.status).toBe(400);
    expect((await tampered.json()).error).toBe('nip44_invalid_mac');

    const wrongPeerPayload = await postJson(r, `/${key.id}/nip44/decrypt`, {
      clientOrigin: origin, peerPubkey: 'b'.repeat(64), payload,
    });
    expect(wrongPeerPayload.status).toBe(400);

    const garbage = await postJson(r, `/${key.id}/nip44/decrypt`, {
      clientOrigin: origin, peerPubkey, payload: 'not base64!!',
    });
    expect(garbage.status).toBe(400);
    expect((await garbage.json()).error).toBe('nip44_payload_invalid');
  });

  test('each operation is granted independently - an encrypt grant does not allow decrypt', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, operations: ['nip44_encrypt'] });
    const res = await postJson(r, `/${key.id}/nip44/decrypt`, {
      clientOrigin: origin, peerPubkey: key.pubkeyHex, payload: 'AA==',
    });
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe('interaction_required');
  });

  test('operations are origin-scoped and user-scoped', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, operations: ['nip44_encrypt'] });

    const wrongOrigin = await postJson(r, `/${key.id}/nip44/encrypt`, {
      clientOrigin: 'http://evil.example.com', peerPubkey: key.pubkeyHex, plaintext: 'x',
    });
    expect(wrongOrigin.status).toBe(403);

    currentUser = otherUser;
    const wrongUser = await postJson(r, `/${key.id}/nip44/encrypt`, {
      clientOrigin: origin, peerPubkey: key.pubkeyHex, plaintext: 'x',
    });
    expect(wrongUser.status).toBe(404);
    currentUser = user;
  });

  test('audit log never contains plaintext or ciphertext bodies', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, operations: ['nip44_encrypt', 'nip44_decrypt'] });
    const secretText = 'the-secret-reminder-body';
    const encrypted = await postJson(r, `/${key.id}/nip44/encrypt`, {
      clientOrigin: origin, peerPubkey: key.pubkeyHex, plaintext: secretText,
    });
    const { ciphertext } = await encrypted.json();
    await postJson(r, `/${key.id}/nip44/decrypt`, {
      clientOrigin: origin, peerPubkey: key.pubkeyHex, payload: ciphertext,
    });
    const serialized = JSON.stringify(decisionRows);
    expect(serialized).not.toContain(secretText);
    expect(serialized).not.toContain(ciphertext);
  });
});

describe('NIP-59 custody operations', () => {
  const origin = 'http://localhost:3000';

  test('wrap produces self-wrap-first gift wraps that recipients can open', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, operations: ['nip59_wrap'] });

    const recipientSecret = generateSecretKey();
    const recipientPubkey = getPublicKey(recipientSecret);
    const res = await postJson(r, `/${key.id}/nip59/wrap`, {
      clientOrigin: origin, content: 'hello in private', recipients: [recipientPubkey],
    });
    expect(res.status).toBe(200);
    const { wraps } = await res.json();
    expect(wraps).toHaveLength(2);
    for (const wrap of wraps) {
      expect(wrap.kind).toBe(1059);
      expect(verifyEvent(wrap as NostrToolsEvent)).toBe(true);
      expect(wrap.pubkey).not.toBe(key.pubkeyHex); // ephemeral signer
    }
    expect(wraps[0].tags).toEqual([['p', key.pubkeyHex]]); // self-wrap first
    expect(wraps[1].tags).toEqual([['p', recipientPubkey]]);
    expect(JSON.stringify(wraps)).not.toContain('hello in private');

    const rumor = nip59.unwrapEvent(wraps[1] as NostrToolsEvent, recipientSecret);
    expect(rumor.kind).toBe(14);
    expect(rumor.content).toBe('hello in private');
    expect(rumor.pubkey).toBe(key.pubkeyHex);
  });

  test('wrap rejects bad recipient lists and stale timestamps', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, operations: ['nip59_wrap'] });
    const pk = getPublicKey(generateSecretKey());

    const cases: Array<Record<string, unknown>> = [
      { content: 'x', recipients: [] },
      { content: 'x', recipients: Array.from({ length: 9 }, () => getPublicKey(generateSecretKey())) },
      { content: 'x', recipients: [pk, pk] },
      { content: 'x', recipients: ['not-hex'] },
      { content: 'x', recipients: [key.pubkeyHex] },
      { content: '', recipients: [pk] },
      { content: 'x'.repeat(4097), recipients: [pk] },
      { content: 'x', recipients: [pk], createdAt: Math.floor(Date.now() / 1000) - 10_000 },
    ];
    for (const body of cases) {
      const res = await postJson(r, `/${key.id}/nip59/wrap`, { clientOrigin: origin, ...body });
      expect(res.status).toBe(400);
    }
  });

  test('unwrap returns the rumor for wraps addressed to this key and rejects others', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, operations: ['nip59_unwrap'] });

    const senderSecret = generateSecretKey();
    const senderPubkey = getPublicKey(senderSecret);
    const rumorTemplate = {
      kind: 14,
      content: 'incoming dm',
      tags: [['p', key.pubkeyHex]],
      created_at: Math.floor(Date.now() / 1000),
    };
    const wrap = nip59.wrapEvent(rumorTemplate, senderSecret, key.pubkeyHex);

    const res = await postJson(r, `/${key.id}/nip59/unwrap`, { clientOrigin: origin, wrap });
    expect(res.status).toBe(200);
    const { rumor } = await res.json();
    expect(rumor.kind).toBe(14);
    expect(rumor.content).toBe('incoming dm');
    expect(rumor.pubkey).toBe(senderPubkey);

    const otherWrap = nip59.wrapEvent(rumorTemplate, senderSecret, getPublicKey(generateSecretKey()));
    const wrongRecipient = await postJson(r, `/${key.id}/nip59/unwrap`, { clientOrigin: origin, wrap: otherWrap });
    expect(wrongRecipient.status).toBe(400);
    expect((await wrongRecipient.json()).error).toBe('nip59_wrong_recipient');

    const tampered = { ...wrap, content: wrap.content.slice(0, -4) + 'AAAA' };
    const tamperedRes = await postJson(r, `/${key.id}/nip59/unwrap`, { clientOrigin: origin, wrap: tampered });
    expect(tamperedRes.status).toBe(400);

    const malformed = await postJson(r, `/${key.id}/nip59/unwrap`, { clientOrigin: origin, wrap: { kind: 1059 } });
    expect(malformed.status).toBe(400);
    expect((await malformed.json()).error).toBe('nip59_wrap_invalid');

    const nonWrap = finalizeEvent({ kind: 1, content: 'x', tags: [], created_at: Math.floor(Date.now() / 1000) }, senderSecret);
    const nonWrapRes = await postJson(r, `/${key.id}/nip59/unwrap`, { clientOrigin: origin, wrap: nonWrap });
    expect(nonWrapRes.status).toBe(400);
  });

  test('audit log never contains DM plaintext for wrap or unwrap', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, operations: ['nip59_wrap', 'nip59_unwrap'] });
    const recipient = getPublicKey(generateSecretKey());
    await postJson(r, `/${key.id}/nip59/wrap`, {
      clientOrigin: origin, content: 'super-private-dm-body', recipients: [recipient],
    });
    const senderSecret = generateSecretKey();
    const wrap = nip59.wrapEvent(
      { kind: 14, content: 'super-private-reply-body', tags: [['p', key.pubkeyHex]], created_at: Math.floor(Date.now() / 1000) },
      senderSecret,
      key.pubkeyHex,
    );
    await postJson(r, `/${key.id}/nip59/unwrap`, { clientOrigin: origin, wrap });
    const serialized = JSON.stringify(decisionRows);
    expect(serialized).not.toContain('super-private-dm-body');
    expect(serialized).not.toContain('super-private-reply-body');
  });
});

describe('revoke races - every result-producing route re-checks before release', () => {
  const origin = 'http://localhost:3000';

  test('sign-event denies when the grant is revoked mid-request', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, { clientOrigin: origin, kinds: [9] });
    const restore = revokeAfterNextGrantLookup();
    try {
      const res = await postSign(r, key.id, {
        pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000), kind: 9, tags: [], content: 'x',
      });
      expect(res.status).toBe(403);
      expect(decisionRows.at(-1)).toMatchObject({ allowed: false, reasonCode: 'grant_revoked_at_signing_time' });
    } finally {
      restore();
    }
  });

  test.each([
    ['nip44/encrypt', () => ({ peerPubkey: '', plaintext: 'x' }), 'nip44_encrypt'],
    ['nip44/decrypt', () => ({ peerPubkey: '', payload: '' }), 'nip44_decrypt'],
    ['nip59/wrap', () => ({ content: 'x', recipients: [getPublicKey(generateSecretKey())] }), 'nip59_wrap'],
    ['nip59/unwrap', () => ({}), 'nip59_unwrap'],
  ] as Array<[string, () => Record<string, unknown>, string]>)(
    '%s denies when the grant is revoked mid-request',
    async (path, makeBody, operation) => {
      const key = await createKey();
      const r = await router();
      await grant(r, key.id, { clientOrigin: origin, operations: [operation] });

      const body = makeBody();
      if (path === 'nip44/encrypt') body.peerPubkey = key.pubkeyHex;
      if (path === 'nip44/decrypt') {
        // Build a real self-ciphertext first, under a temporary encrypt grant.
        await grant(r, key.id, { clientOrigin: origin, operations: ['nip44_encrypt'] });
        const encrypted = await postJson(r, `/${key.id}/nip44/encrypt`, {
          clientOrigin: origin, peerPubkey: key.pubkeyHex, plaintext: 'race',
        });
        body.peerPubkey = key.pubkeyHex;
        body.payload = (await encrypted.json()).ciphertext;
      }
      if (path === 'nip59/unwrap') {
        const senderSecret = generateSecretKey();
        body.wrap = nip59.wrapEvent(
          { kind: 14, content: 'race', tags: [['p', key.pubkeyHex]], created_at: Math.floor(Date.now() / 1000) },
          senderSecret,
          key.pubkeyHex,
        );
      }

      const restore = revokeAfterNextGrantLookup();
      try {
        const res = await postJson(r, `/${key.id}/${path}`, { clientOrigin: origin, ...body });
        expect(res.status).toBe(403);
        expect(decisionRows.at(-1)).toMatchObject({
          allowed: false,
          operation,
          reasonCode: 'grant_revoked_at_signing_time',
        });
      } finally {
        restore();
      }
    },
  );
});

describe('secret non-leakage at the API boundary', () => {
  test('no route response ever contains sealed material or a secret key shape', async () => {
    const key = await createKey();
    const r = await router();
    await grant(r, key.id, {
      clientOrigin: 'http://localhost:3000',
      kinds: [9],
      operations: ['nip44_encrypt', 'nip59_wrap'],
    });

    const responses: unknown[] = [];
    responses.push(await (await r.request('/', { method: 'GET' })).json());
    responses.push(await (await postSign(r, key.id, {
      pubkey: key.pubkeyHex, created_at: Math.floor(Date.now() / 1000), kind: 9, tags: [], content: 'x',
    })).json());
    responses.push(await (await postJson(r, `/${key.id}/nip44/encrypt`, {
      clientOrigin: 'http://localhost:3000', peerPubkey: key.pubkeyHex, plaintext: 'x',
    })).json());
    responses.push(await (await postJson(r, `/${key.id}/nip59/wrap`, {
      clientOrigin: 'http://localhost:3000', content: 'x', recipients: [getPublicKey(generateSecretKey())],
    })).json());

    const sealed = nostrKeyRows[0]!.sealedSecret as string;
    const serialized = JSON.stringify(responses);
    expect(serialized).not.toContain(sealed);
    expect(serialized).not.toContain('sealedSecret');
    expect(serialized).not.toContain('nsec');
  });
});
