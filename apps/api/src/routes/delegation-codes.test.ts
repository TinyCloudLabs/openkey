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
    async get(code) { lookups.push(code); return records.get(code) ?? null; },
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
  test('returns the same public delegation through an eight-character code, then expires it', async () => {
    const { app, advance } = fixture();
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
    expect((await app.request(path)).status).toBe(200);
    advance(10 * 60 * 1000);
    expect((await app.request(path)).status).toBe(404);
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
    records.set('sf23-22cs', { delegation, expiresAt: new Date(now() + 10 * 60 * 1000) });
    for (const variant of ['sf23-22cs', 'SF23-22CS', 'Sf23-22cS']) {
      const fetched = await app.request(`/api/delegation-codes/${variant}`);
      expect(fetched.status).toBe(200);
      expect(await fetched.json()).toEqual({ delegation });
    }
  });

  test('every case variant of one code resolves to the same lookup key', async () => {
    const { app, lookups } = fixture();
    const { code } = await issue(app);
    const variants = [code, code.toLowerCase(), [...code].map((c, i) => (i % 2 ? c.toLowerCase() : c)).join('')];
    for (const variant of variants) expect((await app.request(`/api/delegation-codes/${variant}`)).status).toBe(200);
    expect(new Set(lookups)).toEqual(new Set([code.toLowerCase()]));
  });

  test('keeps the ten-minute expiry for every case variant', async () => {
    const { app, now, advance } = fixture();
    const { code, expiresAt } = await issue(app);
    expect(Date.parse(expiresAt) - now()).toBe(10 * 60 * 1000);
    advance(10 * 60 * 1000 - 1);
    for (const variant of [code, code.toLowerCase()]) expect((await app.request(`/api/delegation-codes/${variant}`)).status).toBe(200);
    advance(1);
    for (const variant of [code, code.toLowerCase()]) expect((await app.request(`/api/delegation-codes/${variant}`)).status).toBe(404);
  });
});
