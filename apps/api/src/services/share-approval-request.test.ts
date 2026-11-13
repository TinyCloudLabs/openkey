import { expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { strictSessionDid } from './device-authorization';
import { ShareApprovalRequests } from './share-approval-request';
import { parsePreparedRecap, isRawRecapEntry } from '../routes/delegate-session';

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
    expiresAt: new Date(now + 1800_000).toISOString(),
    permissions: [{ service: 'tinycloud.kv', space: 'applications', path: 'app/shares/file.json', actions: ['tinycloud.kv/get', 'tinycloud.kv/metadata'] }],
  };
  const account = { userId: 'owner', authSessionId: 'auth-session', keyId: 'key', address: wallet.address, keyType: 'MANAGED' as const };
  return { wallet, intent, account, now };
}

test('the server prepares and signs only its minted exact key and unchanged requested file rows', async () => {
  const f = await fixture();
  const requests = new ShareApprovalRequests(() => f.now);
  const preview = requests.prepare(f.intent, f.account);
  expect(preview.shareId).toMatch(/^[0-9a-f]{32}$/);
  const rows = parsePreparedRecap(preview.prepared.siwe);
  const encryption = rows.filter(isRawRecapEntry);
  expect(encryption).toHaveLength(1);
  expect(encryption[0]!.path).toBe(`urn:tinycloud:encryption:${preview.ownerDid}:default/share/${preview.shareId}`);
  expect(encryption[0]!.actions).toEqual(['tinycloud.encryption/decrypt']);
  expect(rows.filter(row => !isRawRecapEntry(row)).map(row => [row.path, row.actions])).toEqual([
    [f.intent.permissions[0]!.path, f.intent.permissions[0]!.actions],
  ]);
  let consumed = false;
  const result = await requests.sign(preview.requestId, f.account, preview.intentDigest,
    () => { consumed = true; }, message => { expect(consumed).toBe(true); return f.wallet.signMessage(message); });
  expect(result.shareId).toBe(preview.shareId);
  await expect(requests.sign(preview.requestId, f.account, preview.intentDigest, () => {}, message => f.wallet.signMessage(message))).rejects.toThrow();
});

test('changed auth session or intent and missing fresh approval cannot sign', async () => {
  const f = await fixture();
  const requests = new ShareApprovalRequests(() => f.now);
  const preview = requests.prepare(f.intent, f.account);
  await expect(requests.sign(preview.requestId, { ...f.account, authSessionId: 'other' }, preview.intentDigest, () => {}, message => f.wallet.signMessage(message))).rejects.toThrow();
  await expect(requests.sign(preview.requestId, f.account, 'changed', () => {}, message => f.wallet.signMessage(message))).rejects.toThrow();
  await expect(requests.sign(preview.requestId, f.account, preview.intentDigest, () => { throw new Error('fresh UV missing'); }, message => f.wallet.signMessage(message))).rejects.toThrow();
  expect(requests.preview(preview.requestId, f.account).intentDigest).toBe(preview.intentDigest);
});
