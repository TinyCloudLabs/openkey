import { test, expect } from 'bun:test';
import { Wallet } from 'ethers';
import { generateKeyPairSync } from 'node:crypto';
import { SiweMessage } from 'siwe';
import { strictSessionDid } from './device-authorization';
import { ShareApprovalRequests } from './share-approval-request';
import { ShareWindowContexts } from './share-window-context';
test('final UV claim and share spend are terminal before yielding to cancellation or replay', async () => {
  const wallet = Wallet.createRandom();
  const publicJwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const now = Date.now();
  const siwe = new SiweMessage({ domain: 'thirdparty.example', address: wallet.address, uri: strictSessionDid(publicJwk), version: '1', chainId: 1, nonce: '12345678', issuedAt: new Date(now).toISOString(), expirationTime: new Date(now + 3600_000).toISOString() }).prepareMessage();
  const account = { userId: 'owner', authSessionId: 'session-A', authSessionGeneration: 'generation', keyId: 'key', address: wallet.address, keyType: 'EXTERNAL' as const };
  const windows = new ShareWindowContexts(() => now);
  const requests = new ShareApprovalRequests(() => now);
  const w = windows.issue(account, 'outer', 'https://thirdparty.example');
  const preview = requests.prepare({ keyId: 'key', origin: 'https://thirdparty.example', session: { siwe, signature: await wallet.signMessage(siwe), publicJwk }, expiresAt: new Date(now + 1800_000).toISOString() }, account, w.context, () => windows.consume(w.token, account, 'outer'));
  let uvClaims = 0;
  const pending = requests.sign(preview.requestId, account, preview.intentDigest, () => { if (uvClaims++) throw new Error('UV spent'); }, message => wallet.signMessage(message));
  // A concurrent cancellation must see a terminal request immediately, not steal an in-flight claim.
  expect(() => requests.cancel(preview.requestId, account)).toThrow();
  await expect(requests.sign(preview.requestId, account, preview.intentDigest, () => { throw new Error('UV spent'); }, message => wallet.signMessage(message))).rejects.toThrow();
  expect((await pending).shareId).toBe(preview.shareId);
  expect(uvClaims).toBe(1);
});
