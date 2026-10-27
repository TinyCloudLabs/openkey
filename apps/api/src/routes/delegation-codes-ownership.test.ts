import { expect, test } from 'bun:test';
import { Hono, type MiddlewareHandler } from 'hono';
import { createMiddleware } from 'hono/factory';
import { createDelegationCodeRouter, type DelegationCodeStore } from './delegation-codes';
import type { SessionContext } from '../middleware/session';

const delegation = {
  delegationHeader: { Authorization: 'Bearer signed' },
  delegationCid: 'bafy-signed',
  spaceId: 'tinycloud:pkh:eip155:1:0x123:default',
  ownerDid: 'did:pkh:eip155:1:0x123',
  verificationMethod: 'did:key:zSession',
  jwk: { kty: 'OKP', crv: 'Ed25519', x: 'public-key' },
  address: '0x123',
  signature: '0xsigned-by-another-user',
  signedMessage: 'approved SIWE',
};

test('does not host a delegation the authenticated account did not approve', async () => {
  const records = new Map<string, unknown>();
  const store: DelegationCodeStore = {
    async create(code, value) { records.set(code, value); return true; },
    async consume() { return null; },
    async deleteExpired() {},
  };
  const sessionMiddleware: MiddlewareHandler<SessionContext> = createMiddleware<SessionContext>(async (context, next) => {
    context.set('user', { id: 'current-user', email: 'current@example.test' });
    context.set('session', { id: 'session-1', userId: 'current-user', expiresAt: new Date(Date.now() + 60_000) });
    await next();
  });
  const routerInput = {
    store,
    sessionMiddleware,
    refreshGrantSecret: 'test-refresh-grant-secret',
    isDelegationOwnedByUser: async (_userId: string, _submitted: unknown) => false,
  };
  const app = new Hono<SessionContext>().route('/api/delegation-codes', createDelegationCodeRouter(routerInput));

  const response = await app.request('/api/delegation-codes', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ delegation }),
  });

  expect(response.status).toBe(403);
  expect(records.size).toBe(0);
});
