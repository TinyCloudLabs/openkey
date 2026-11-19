import { expect, test } from 'bun:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { buildOwnerRevocationSiwe } from '@openkey/capability-review';
import { completeSessionSetup, generateHostSIWEMessage, invoke, siweToDelegationHeaders } from '@tinycloud/node-sdk-wasm';
import { prepareDelegationSession } from '../routes/delegate-session';

const nodeUrl = process.env.OPENKEY_TEST_TINYCLOUD_REVOKE_NODE_URL;

test.skipIf(!nodeUrl)('local TinyCloud node accepts owner-signed revoke and refuses a revoked session invocation', async () => {
  const node = new URL(nodeUrl!);
  expect(node.protocol).toBe('http:');
  expect(['127.0.0.1', '::1', 'localhost']).toContain(node.hostname);
  const host = node.origin;

  const owner = privateKeyToAccount(`0x${randomBytes(32).toString('hex')}` as `0x${string}`);
  const exportedJwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
  if (exportedJwk.kty !== 'OKP' || exportedJwk.crv !== 'Ed25519' ||
      typeof exportedJwk.x !== 'string' || typeof exportedJwk.d !== 'string') {
    throw new Error('test session key is not a private Ed25519 JWK');
  }
  const jwk = { kty: exportedJwk.kty, crv: exportedJwk.crv, x: exportedJwk.x, d: exportedJwk.d };
  const preparation = prepareDelegationSession({
    address: owner.address,
    chainId: 1,
    prefix: 'applications',
    jwk,
    expiryMs: 5 * 60_000,
    domain: 'openkey.so',
  });
  const sessionSiwe = preparation.prepared.siwe;
  const sessionSignature = await owner.signMessage({ message: sessionSiwe });
  const session = completeSessionSetup({ ...preparation.prepared, signature: sessionSignature });

  const peerResponse = await fetch(`${host}/peer/generate/${encodeURIComponent(preparation.spaceId)}`);
  expect(peerResponse.status).toBe(200);
  const peerId = (await peerResponse.text()).trim();
  expect(peerId.startsWith('did:key:')).toBe(true);
  const hostSiwe = generateHostSIWEMessage({
    address: owner.address,
    chainId: 1,
    domain: 'openkey.so',
    issuedAt: new Date().toISOString(),
    spaceId: preparation.spaceId,
    peerId,
  });
  const hosting = await fetch(`${host}/delegate`, {
    method: 'POST',
    headers: siweToDelegationHeaders({ siwe: hostSiwe, signature: await owner.signMessage({ message: hostSiwe }) }),
    redirect: 'error',
  });
  expect(hosting.status).toBe(200);
  expect(await hosting.json()).toMatchObject({ activated: [preparation.spaceId] });

  const activated = await fetch(`${host}/delegate`, {
    method: 'POST',
    headers: session.delegationHeader,
    redirect: 'error',
  });
  expect(activated.status).toBe(200);
  const activationBody: unknown = await activated.json();
  expect(activationBody).toMatchObject({ cid: session.delegationCid });

  const invokeCapabilities = async () => fetch(`${host}/invoke`, {
    method: 'POST',
    headers: { ...invoke(session, 'capabilities', '', 'tinycloud.capabilities/read', null), 'Content-Type': 'application/json' },
    body: '{}',
    redirect: 'error',
  });
  const beforeRevoke = await invokeCapabilities();
  expect(beforeRevoke.status, await beforeRevoke.clone().text()).toBe(200);

  const issuedAt = new Date();
  const revocationSiwe = buildOwnerRevocationSiwe({
    kind: 'owner-revocation',
    ownerDid: `did:pkh:eip155:1:${owner.address}`,
    cid: session.delegationCid,
    nonce: randomBytes(16).toString('hex'),
    expiresAt: new Date(issuedAt.getTime() + 600_000).toISOString(),
  }, 'openkey.so', issuedAt);
  const revocation = await fetch(`${host}/revoke`, {
    method: 'POST',
    headers: siweToDelegationHeaders({
      siwe: revocationSiwe,
      signature: await owner.signMessage({ message: revocationSiwe }),
    }),
    redirect: 'error',
  });
  expect(revocation.status).toBe(200);
  expect(await revocation.json()).toEqual({ revoked: true, cid: session.delegationCid });

  const afterRevoke = await invokeCapabilities();
  expect([401, 403]).toContain(afterRevoke.status);
}, 20_000);
