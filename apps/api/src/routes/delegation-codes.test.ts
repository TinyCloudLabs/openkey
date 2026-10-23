import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { createDelegationCodeRouter, type DelegationCodeStore } from './delegation-codes';

const delegation = {
  delegationHeader: { Authorization: 'Bearer signed-delegation' },
  delegationCid: 'bafy-delegation',
  spaceId: 'tinycloud:pkh:eip155:1:0x123:default',
  verificationMethod: 'did:key:zSession',
  jwk: { kty: 'OKP', crv: 'Ed25519', x: 'public-key' },
  primary: true,
  spaceReady: false,
  spaceError: 'TinyCloud account setup failed (tinycloud_bootstrap_failed): seed failed.',
  expirationTime: '2099-01-01T00:00:00.000Z',
};

function fixture() {
  let now = Date.UTC(2026, 9, 5);
  const records = new Map<string, { delegation: unknown; expiresAt: Date }>();
  const lookups: string[] = [];
  const store: DelegationCodeStore = {
    async create(code, value, expiresAt) {
      if (records.has(code)) return false;
      records.set(code, { delegation: value, expiresAt });
      return true;
    },
    async consume(code) { lookups.push(code); const record = records.get(code); records.delete(code); return record ?? null; },
    async deleteExpired(before) {
      for (const [code, record] of records) if (record.expiresAt <= before) records.delete(code);
    },
  };
  const app = new Hono().route('/api/delegation-codes', createDelegationCodeRouter({
    store,
    now: () => new Date(now),
    sessionMiddleware: async (_c, next) => next(),
  }));
  return { app, records, lookups, now: () => now, advance: (ms: number) => { now += ms; } };
}

async function issue(app: Hono) {
  const created = await app.request('/api/delegation-codes', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ delegation }),
  });
  expect(created.status).toBe(201);
  return await created.json() as { code: string; expiresAt: string };
}

describe('delegation short-code broker', () => {
  test('returns the public delegation once, then the code is gone', async () => {
    const { app } = fixture();
    const created = await app.request('/api/delegation-codes', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ delegation }),
    });
    expect(created.status).toBe(201);
    const { code } = await created.json() as { code: string };
    expect(code).toMatch(/^[A-Z2-7]{4}-[A-Z2-7]{4}$/);
    const path = `/api/delegation-codes/${code}`;
    const fetched = await app.request(path);
    expect(fetched.status).toBe(200);
    expect(await fetched.json()).toEqual({ delegation });
    const again = await app.request(path);
    expect(again.status).toBe(404);
    expect(await again.json()).toEqual({ error: 'Not found' });
  });

  test('a redeemed code answers exactly like an unknown one', async () => {
    const { app } = fixture();
    const { code } = await issue(app);
    await app.request(`/api/delegation-codes/${code}`);
    const redeemed = await app.request(`/api/delegation-codes/${code}`);
    const unknown = await app.request('/api/delegation-codes/sf23-22cs');
    expect(redeemed.status).toBe(404);
    expect(unknown.status).toBe(404);
    expect(await redeemed.text()).toBe(await unknown.text());
  });

  test('an expired code answers exactly like an unknown one', async () => {
    const { app, advance } = fixture();
    const { code } = await issue(app);
    advance(5 * 60 * 1000);
    const expired = await app.request(`/api/delegation-codes/${code}`);
    const unknown = await app.request('/api/delegation-codes/sf23-22cs');
    expect(expired.status).toBe(404);
    expect(unknown.status).toBe(404);
    expect(await expired.text()).toBe(await unknown.text());
  });

  test('a malformed code answers exactly like an unknown one', async () => {
    const { app } = fixture();
    const malformed = await app.request('/api/delegation-codes/abc');
    const unknown = await app.request('/api/delegation-codes/sf23-22cs');
    expect(malformed.status).toBe(404);
    expect(await malformed.text()).toBe(await unknown.text());
  });

  test('lookups are never cached, whatever the outcome', async () => {
    const { app } = fixture();
    const { code } = await issue(app);
    const fetched = await app.request(`/api/delegation-codes/${code}`);
    const missing = await app.request('/api/delegation-codes/sf23-22cs');
    expect(fetched.status).toBe(200);
    expect(fetched.headers.get('cache-control')).toBe('no-store');
    expect(missing.headers.get('cache-control')).toBe('no-store');
  });

  test('of concurrent redeems of one code, exactly one receives the delegation', async () => {
    const { app } = fixture();
    const { code } = await issue(app);
    const responses = await Promise.all(Array.from({ length: 10 }, () => app.request(`/api/delegation-codes/${code}`)));
    const statuses = responses.map((response) => response.status);
    expect(statuses.filter((status) => status === 200)).toHaveLength(1);
    expect(statuses.filter((status) => status === 404)).toHaveLength(9);
  });

  test('caps redeem attempts at 60 per minute, then recovers after the window', async () => {
    const { app, advance } = fixture();
    const lookup = () => app.request('/api/delegation-codes/sf23-22cs');
    for (let index = 0; index < 60; index += 1) expect((await lookup()).status).toBe(404);
    const limited = await lookup();
    expect(limited.status).toBe(429);
    expect(limited.headers.get('retry-after')).toBe('60');
    expect(limited.headers.get('cache-control')).toBe('no-store');
    advance(60 * 1000);
    expect((await lookup()).status).toBe(404);
  });

  test('refuses a delegation containing private JWK material', async () => {
    const { app } = fixture();
    const response = await app.request('/api/delegation-codes', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ delegation: { ...delegation, jwk: { ...delegation.jwk, d: 'secret' } } }),
    });
    expect(response.status).toBe(400);
  });

  test('does not publish arbitrary fields alongside the signed delegation', async () => {
    const { app } = fixture();
    const response = await app.request('/api/delegation-codes', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ delegation: { ...delegation, privateKey: 'never-public' } }),
    });
    expect(response.status).toBe(400);
    const nested = await app.request('/api/delegation-codes', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ delegation: { ...delegation, jwk: { ...delegation.jwk, secret: 'never-public' } } }),
    });
    expect(nested.status).toBe(400);
    const disguised = await app.request('/api/delegation-codes', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ delegation: { ...delegation, primary: { privateKey: 'never-public' } } }),
    });
    expect(disguised.status).toBe(400);
  });
});


describe('TC-945 pending delegation short codes', () => {
  test('round-trips pending readiness through POST and GET', async () => {
    const { app } = fixture();
    const { spaceError: _error, ...publicDelegation } = delegation;
    const pending = { ...publicDelegation, spaceReady: null, spacePending: true };
    const created = await app.request('/api/delegation-codes', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ delegation: pending }),
    });
    expect(created.status).toBe(201);
    const { code } = await created.json() as { code: string };
    const fetched = await app.request(`/api/delegation-codes/${code}`);
    expect(fetched.status).toBe(200);
    expect(await fetched.json()).toEqual({ delegation: pending });
  });
  for (const spacePending of [false, 'yes']) {
    test(`rejects spacePending ${JSON.stringify(spacePending)}`, async () => {
      const { app } = fixture();
      const response = await app.request('/api/delegation-codes', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ delegation: { ...delegation, spaceReady: null, spacePending } }),
      });
      expect(response.status).toBe(400);
    });
  }
});

describe('upper-case delegation short codes', () => {
  test('issues codes from the full 32-symbol upper-case base32 alphabet only', async () => {
    const { app } = fixture();
    const seen = new Set<string>();
    for (let index = 0; index < 300; index += 1) {
      const { code } = await issue(app);
      expect(code).toMatch(/^[A-Z2-7]{4}-[A-Z2-7]{4}$/);
      for (const symbol of code.replace('-', '')) seen.add(symbol);
    }
    // 2,400 draws: every symbol appears unless the alphabet shrank.
    expect([...seen].sort().join('')).toBe('234567ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  });

  test('stores the lower-case canonical form that older CLIs look up', async () => {
    const { app, records } = fixture();
    const { code } = await issue(app);
    expect([...records.keys()]).toEqual([code.toLowerCase()]);
  });

  test('a code issued in lower case before the change redeems in any case', async () => {
    const { app, records, now } = fixture();
    for (const variant of ['sf23-22cs', 'SF23-22CS', 'Sf23-22cS']) {
      records.set('sf23-22cs', { delegation, expiresAt: new Date(now() + 5 * 60 * 1000) });
      const fetched = await app.request(`/api/delegation-codes/${variant}`);
      expect(fetched.status).toBe(200);
      expect(await fetched.json()).toEqual({ delegation });
    }
  });

  test('every case variant of one code resolves to the same lookup key', async () => {
    const { app, lookups } = fixture();
    for (const spelling of ['lower', 'upper', 'mixed'] as const) {
      const { code } = await issue(app);
      const variant = spelling === 'lower' ? code.toLowerCase()
        : spelling === 'upper' ? code
          : [...code].map((c, i) => (i % 2 ? c.toLowerCase() : c)).join('');
      expect((await app.request(`/api/delegation-codes/${variant}`)).status).toBe(200);
      expect(lookups.at(-1)).toBe(code.toLowerCase());
    }
  });

  test('keeps the five-minute expiry for every case variant', async () => {
    const { app, now, advance } = fixture();
    const { code, expiresAt } = await issue(app);
    expect(Date.parse(expiresAt) - now()).toBe(5 * 60 * 1000);
    advance(5 * 60 * 1000 - 1);
    expect((await app.request(`/api/delegation-codes/${code.toLowerCase()}`)).status).toBe(200);
    const late = await issue(app);
    advance(5 * 60 * 1000);
    expect((await app.request(`/api/delegation-codes/${late.code}`)).status).toBe(404);
  });
});
