// TC-2788: what a short code carries. The /delegate page sends the broker only the public fields of a completion
// response, and the broker hands back exactly those. Names every object inherits (`constructor`, `toString`) and
// `__proto__`, which JSON.parse makes an own key, are not on the allowlists and are refused.
import { expect, test } from 'bun:test';
import { Hono } from 'hono';
import { publicDelegationForCode } from '../../../web/src/lib/delegation-code-body';
import { createDelegationCodeRouter, type DelegationCodeStore } from './delegation-codes';

function broker() {
  const records = new Map<string, unknown>();
  const store: DelegationCodeStore = {
    async create(code, value) { records.set(code, value); return true; },
    async consume(code) {
      const delegation = records.get(code);
      records.delete(code);
      return delegation === undefined ? null : { delegation, expiresAt: new Date(Date.UTC(2099, 0, 1)) };
    },
    async claim() { throw new Error('not used'); },
    async acknowledge() { throw new Error('not used'); },
    async deleteExpired() {},
  };
  const app = new Hono().route('/api/delegation-codes', createDelegationCodeRouter({
    store, now: () => new Date(Date.UTC(2026, 9, 5)), sessionMiddleware: async (_c, next) => next(),
  }));
  // A raw body: an object literal's `__proto__` would never reach the wire as a key.
  const post = (body: string) => app.request('/api/delegation-codes', { method: 'POST', headers: { 'content-type': 'application/json' }, body });
  return { app, records, post };
}

test('the page payload and the broker payload carry the same public fields and no private ones', async () => {
  // A completion response as /api/delegate answers it, with the fields that must never reach the broker.
  const completion = {
    delegationHeader: { Authorization: 'Bearer signed-delegation' }, delegationCid: 'bafy-delegation',
    spaceId: 'tinycloud:pkh:eip155:1:0x123:default', ownerDid: 'did:pkh:eip155:1:0x123', verificationMethod: 'did:key:zSession',
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'public-key', kid: 'session', d: 'private-key' },
    address: '0x123', chainId: 1, hostActivated: true, spaceReady: true, primary: true,
    expirationTime: '2099-01-01T00:00:00.000Z', siwe: 'signed message', signature: '0xsig',
    requestedSpaces: ['tinycloud:pkh:eip155:1:0x123:private'],
  };
  const page = publicDelegationForCode(completion);
  const { app, post } = broker();
  const created = await post(JSON.stringify({ delegation: page }));
  expect(created.status).toBe(201);
  const { code } = await created.json() as { code: string };
  const redeemed = await app.request(`/api/delegation-codes/${code}`);
  expect(redeemed.status).toBe(200);
  const { delegation: brokered } = await redeemed.json() as { delegation: Record<string, unknown> & { jwk: Record<string, unknown> } };
  const pageJwk = page.jwk as Record<string, unknown>;

  expect(Object.keys(brokered).sort()).toEqual(Object.keys(page).sort());
  expect(Object.keys(brokered.jwk).sort()).toEqual(Object.keys(pageJwk).sort());
  for (const payload of [page, brokered]) {
    expect(payload).not.toHaveProperty('requestedSpaces');
    expect(payload.jwk).not.toHaveProperty('d');
  }
  expect(brokered).toEqual(page);
});

test('a delegation with only public fields is stored', async () => {
  const { post, records } = broker();
  expect((await post(body(''))).status).toBe(201);
  expect(records.size).toBe(1);
});

const jwk = '"kty":"OKP","crv":"Ed25519","x":"public-key"';
const fields = '"delegationHeader":{"Authorization":"Bearer signed-delegation"},"delegationCid":"bafy-delegation",'
  + '"spaceId":"tinycloud:pkh:eip155:1:0x123:default","verificationMethod":"did:key:zSession"';
function body(jwkExtra: string, delegationExtra = '') {
  return `{"delegation":{${fields},"jwk":{${jwk}${jwkExtra}}${delegationExtra}}}`;
}

for (const name of ['constructor', 'toString', '__proto__']) {
  test(`a jwk carrying "${name}" is refused and nothing is stored`, async () => {
    const { post, records } = broker();
    expect((await post(body(`,"${name}":"secret"`))).status).toBe(400);
    expect(records.size).toBe(0);
  });
  test(`a delegation carrying "${name}" is refused and nothing is stored`, async () => {
    const { post, records } = broker();
    expect((await post(body('', `,"${name}":"secret"`))).status).toBe(400);
    expect(records.size).toBe(0);
  });
}
