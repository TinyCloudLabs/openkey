import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { createDelegationCodeRouter, type DelegationCodeStore } from './delegation-codes';

const delegation = {
  delegationHeader: { Authorization: 'Bearer signed-delegation' },
  delegationCid: 'bafy-delegation',
  spaceId: 'tinycloud:pkh:eip155:1:0x123:default',
  verificationMethod: 'did:key:zSession',
  jwk: { kty: 'OKP', crv: 'Ed25519', x: 'public-key' },
  expirationTime: '2099-01-01T00:00:00.000Z',
};

function fixture() {
  let now = Date.UTC(2026, 9, 5);
  const records = new Map<string, { delegation: unknown; expiresAt: Date }>();
  const store: DelegationCodeStore = {
    async create(code, value, expiresAt) {
      if (records.has(code)) return false;
      records.set(code, { delegation: value, expiresAt });
      return true;
    },
    async get(code) { return records.get(code) ?? null; },
    async deleteExpired(before) {
      for (const [code, record] of records) if (record.expiresAt <= before) records.delete(code);
    },
  };
  const app = new Hono().route('/api/delegation-codes', createDelegationCodeRouter({
    store,
    now: () => new Date(now),
    sessionMiddleware: async (_c, next) => next(),
  }));
  return { app, advance: (ms: number) => { now += ms; } };
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
    expect(code).toMatch(/^[a-z2-7]{4}-[a-z2-7]{4}$/);
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
  });
});
