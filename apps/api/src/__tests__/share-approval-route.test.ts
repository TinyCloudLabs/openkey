import './tc1777-test-env';
import { expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { createMiddleware } from 'hono/factory';
import type { SessionContext } from '../middleware/session';
import { createShareApprovalRouter, type ShareApprovalLifecycle } from '../routes/share-approval';
import { ShareApprovalRequests } from '../services/share-approval-request';
import { strictSessionDid } from '../services/device-authorization';

async function fixture() {
  const wallet = Wallet.createRandom();
  const publicJwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const now = Date.now();
  const siwe = new SiweMessage({ domain: 'thirdparty.example', address: wallet.address,
    uri: strictSessionDid(publicJwk), version: '1', chainId: 1, nonce: '12345678',
    issuedAt: new Date(now - 1000).toISOString(), expirationTime: new Date(now + 3600_000).toISOString(),
  }).prepareMessage();
  const intent = { origin: 'https://thirdparty.example', keyId: 'key',
    session: { siwe, signature: await wallet.signMessage(siwe), publicJwk },
    expiresAt: new Date(now + 1800_000).toISOString() };
  const account = { userId: 'owner', authSessionId: 'auth-session', keyId: 'key', address: wallet.address, keyType: 'MANAGED' as const };
  const pending = new Map<string, { digest: string; verified: boolean; resumed: boolean }>();
  const state = (preview: { requestId: string; intentDigest: string }, token: string) => {
    const record = pending.get(preview.requestId);
    if (!record || token !== preview.requestId || record.digest !== preview.intentDigest) throw new Error('changed continuation');
    return record;
  };
  const lifecycle: ShareApprovalLifecycle = {
    async options(preview) { pending.set(preview.requestId, { digest: preview.intentDigest, verified: false, resumed: false }); return { token: preview.requestId }; },
    async verify(preview, _account, token) { state(preview, token).verified = true; },
    resume(preview, _account, token) { const record = state(preview, token); if (!record.verified) throw new Error('UV missing'); record.resumed = true; },
    assertResumed(preview, _account, token) { if (!state(preview, token).resumed) throw new Error('UV missing'); },
    consume(preview, account, token) { this.assertResumed(preview, account, token); pending.delete(preview.requestId); },
    cancel(preview, _account, token) { state(preview, token); pending.delete(preview.requestId); },
  };
  let signed = 0;
  // Replace only the wallet transport, not SIWE preparation, parsing or signature checks.
  const depsRouter = createShareApprovalRouter(new ShareApprovalRequests(() => now), {
    findAccount: async () => ({ ...account }),
    signManaged: async (_account, message) => { signed++; return wallet.signMessage(message); }, lifecycle,
  }, createMiddleware<SessionContext>(async (c, next) => {
    c.set('user', { id: account.userId } as never); c.set('session', { id: account.authSessionId } as never); await next();
  }));
  const call = (path: string, body: unknown, headers: Record<string, string> = {}) => depsRouter.request(`http://api.test/${path}`, {
    method: 'POST', headers: { origin: 'http://localhost:5173', 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
  });
  return { call, intent, signed: () => signed };
}

test('typed new-share route requires fresh approval and signs once', async () => {
  const f = await fixture();
  const options = await f.call('options', { intent: f.intent });
  expect(options.status).toBe(200);
  const preview = await options.json() as any;
  const request = { requestId: preview.requestId, keyId: 'key', token: preview.assertion.token };
  expect((await f.call('sign', request)).status).toBe(403);
  expect(f.signed()).toBe(0);
  expect((await f.call('verify', { ...request, response: { fixture: true } })).status).toBe(200);
  expect((await f.call('resume', request)).status).toBe(200);
  expect((await f.call('sign', { ...request, siwe: 'caller bytes' })).status).toBe(400);
  const signed = await f.call('sign', request);
  expect(signed.status).toBe(200);
  expect((await signed.json() as any).shareId).toBe(preview.shareId);
  expect((await f.call('sign', request)).status).toBe(403);
  expect(f.signed()).toBe(1);
});

test('caller ids, off-origin controls and bearer signing are refused', async () => {
  const f = await fixture();
  expect((await f.call('options', { intent: { ...f.intent, shareId: 'existing-share-id' } })).status).toBe(403);
  expect((await f.call('options', { intent: f.intent }, { origin: 'https://thirdparty.example' })).status).toBe(403);
  expect((await f.call('options', { intent: f.intent }, { authorization: 'Bearer fixture' })).status).toBe(403);
  expect(f.signed()).toBe(0);
});
