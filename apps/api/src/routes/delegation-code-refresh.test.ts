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
  signature: '0xsigned-by-owner',
  signedMessage: 'approved SIWE',
};

function testServer(userId: string, sessionId: string) {
  const records = new Map<string, { delegation: unknown; expiresAt: Date }>();
  let codeNumber = 0;
  const store: DelegationCodeStore = {
    async create(code, value, expiresAt) {
      records.set(code, { delegation: value, expiresAt });
      return true;
    },
    async consume(code) { const record = records.get(code); records.delete(code); return record ?? null; },
    async deleteExpired(before) {
      for (const [code, record] of records) if (record.expiresAt <= before) records.delete(code);
    },
  };
  const sessionMiddleware: MiddlewareHandler<SessionContext> = createMiddleware<SessionContext>(async (context, next) => {
    context.set('user', { id: userId, email: `${userId}@example.test` });
    context.set('session', { id: sessionId, userId, expiresAt: new Date(Date.now() + 60_000) });
    await next();
  });
  const routerInput = {
    store,
    sessionMiddleware,
    refreshGrantSecret: 'test-refresh-grant-secret',
    isDelegationOwnedByUser: async (candidateUser: string, submitted: unknown) =>
      candidateUser === 'owner' && JSON.stringify(submitted) === JSON.stringify(delegation),
  };
  const app = new Hono<SessionContext>().route('/api/delegation-codes', createDelegationCodeRouter(routerInput));
  return { app, records };
}

async function post(app: Hono<SessionContext>, path: string, body: unknown) {
  return app.request(`/api/delegation-codes${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

test('refresh creates a new code for the same approved delegation and session', async () => {
  const { app, records } = testServer('owner', 'approval-session');
  const initial = await post(app, '', { delegation });
  expect(initial.status).toBe(201);
  const initialResult = await initial.json() as { code: string; refreshGrant: string };
  expect(initialResult.refreshGrant).toBeTruthy();

  const refreshed = await post(app, '/refresh', { delegation, refreshGrant: initialResult.refreshGrant });
  expect(refreshed.status).toBe(201);
  const refreshedResult = await refreshed.json() as { code: string };
  expect(refreshedResult.code).not.toBe(initialResult.code);
  expect([...records.values()].map((record) => record.delegation)).toEqual([delegation, delegation]);
});

test('refresh refuses a different page session or a changed delegation', async () => {
  const { app } = testServer('owner', 'approval-session');
  const initial = await post(app, '', { delegation });
  const { refreshGrant } = await initial.json() as { refreshGrant: string };
  const differentSession = testServer('owner', 'another-session');
  const stolenSessionResponse = await post(differentSession.app, '/refresh', { delegation, refreshGrant });
  expect(stolenSessionResponse.status).toBe(403);

  const changedDelegation = { ...delegation, delegationCid: 'bafy-different' };
  const changedPayloadResponse = await post(app, '/refresh', { delegation: changedDelegation, refreshGrant });
  expect(changedPayloadResponse.status).toBe(403);
});
