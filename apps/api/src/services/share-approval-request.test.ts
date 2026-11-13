import { expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { strictSessionDid } from './device-authorization';
import { ShareWindowContexts } from './share-window-context';
import { ShareApprovalRequests } from './share-approval-request';
import { parsePreparedRecap, isRawRecapEntry, prepareDelegationSession, type DelegationJwk } from '../routes/delegate-session';

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
  const account = { userId: 'owner', authSessionId: 'auth-session', authSessionGeneration: 'generation', keyId: 'key', address: wallet.address, keyType: 'MANAGED' as const };
  return { wallet, intent, account, now };
}

function prepare(requests: ShareApprovalRequests, f: Awaited<ReturnType<typeof fixture>>, intent = f.intent) {
  const windows = new ShareWindowContexts(() => f.now);
  const outer = crypto.randomUUID();
  const window = windows.issue(f.account, outer, f.intent.origin);
  return requests.prepare(intent, f.account, window.context, () => windows.consume(window.token, f.account, outer));
}

test('the server prepares and signs only its minted exact key and unchanged requested file rows', async () => {
  const f = await fixture();
  const requests = new ShareApprovalRequests(() => f.now);
  const preview = prepare(requests, f);
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
  const preview = prepare(requests, f);
  await expect(requests.sign(preview.requestId, { ...f.account, authSessionId: 'other' }, preview.intentDigest, () => {}, message => f.wallet.signMessage(message))).rejects.toThrow();
  await expect(requests.sign(preview.requestId, f.account, 'changed', () => {}, message => f.wallet.signMessage(message))).rejects.toThrow();
  await expect(requests.sign(preview.requestId, f.account, preview.intentDigest, () => { throw new Error('fresh UV missing'); }, message => f.wallet.signMessage(message))).rejects.toThrow();
  expect(() => requests.preview(preview.requestId, f.account)).toThrow();
});


test('grant expiry is clamped by the signed session and rechecked after signing', async () => {
  const f = await fixture();
  let now = f.now;
  const requests = new ShareApprovalRequests(() => now);
  expect(() => prepare(requests, f, { ...f.intent, expiresAt: new Date(now + 7200_000).toISOString() })).toThrow();
  const preview = prepare(requests, f);
  await expect(requests.sign(preview.requestId, f.account, preview.intentDigest, () => {}, async message => {
    const signature = await f.wallet.signMessage(message);
    now += 3600_000;
    return signature;
  })).rejects.toThrow();
});


test('a claimed origin cannot replace the observed window origin', async () => {
  const f = await fixture();
  const windows = new ShareWindowContexts(() => f.now);
  const window = windows.issue(f.account, 'outer', 'https://actual-attacker.example');
  const requests = new ShareApprovalRequests(() => f.now);
  expect(() => requests.prepare(f.intent, f.account, window.context,
    () => windows.consume(window.token, f.account, 'outer'))).toThrow('binding_mismatch');
  expect(windows.read(window.token, f.account, 'outer')).toBe(window.context);
});


test('sign refuses added space-scoped encryption actions even beyond the exact-byte fence', async () => {
  const f = await fixture();
  const requests = new ShareApprovalRequests(() => f.now);
  const preview = prepare(requests, f);
  const { prepared } = prepareDelegationSession({
    address: f.wallet.address, chainId: 1, prefix: 'applications',
    jwk: f.intent.session.publicJwk as DelegationJwk, domain: 'thirdparty.example',
    nonce: '12345678', issuedAt: new Date(f.now), expiryMs: 1800_000,
    permissions: [...f.intent.permissions,
      { service: 'tinycloud.encryption', space: 'encryption',
        path: `urn:tinycloud:encryption:${preview.ownerDid}:default/share/${preview.shareId}`,
        actions: ['tinycloud.encryption/decrypt'] },
      { service: 'tinycloud.encryption', space: 'applications', path: 'other-key',
        actions: ['tinycloud.encryption/key.create'] }],
  });
  // Probe corrupted internal state, independently of the immutable-byte guard.
  const record = (requests as any).requests.get(preview.requestId);
  record.prepared = prepared;
  record.originalSiwe = prepared.siwe;
  let consumed = false;
  await expect(requests.sign(preview.requestId, f.account, preview.intentDigest,
    () => { consumed = true; }, message => f.wallet.signMessage(message))).rejects.toThrow('scope_mismatch');
  expect(consumed).toBe(false);
});

test('sign refuses changed ordinary file rows before consuming approval', async () => {
  const f = await fixture();
  const requests = new ShareApprovalRequests(() => f.now);
  const preview = prepare(requests, f);
  const record = (requests as any).requests.get(preview.requestId);
  const { prepared } = prepareDelegationSession({
    address: f.wallet.address, chainId: 1, prefix: 'applications',
    jwk: f.intent.session.publicJwk as DelegationJwk, domain: 'thirdparty.example',
    nonce: '12345678', issuedAt: new Date(f.now), expiryMs: 1800_000,
    permissions: [{ ...f.intent.permissions[0]!, path: 'app/private/file.json' },
      { service: 'tinycloud.encryption', space: 'encryption',
        path: `urn:tinycloud:encryption:${preview.ownerDid}:default/share/${preview.shareId}`,
        actions: ['tinycloud.encryption/decrypt'] }],
  });
  record.prepared = prepared;
  let consumed = false;
  await expect(requests.sign(preview.requestId, f.account, preview.intentDigest,
    () => { consumed = true; }, message => f.wallet.signMessage(message))).rejects.toThrow('scope_mismatch');
  expect(consumed).toBe(false);
});
