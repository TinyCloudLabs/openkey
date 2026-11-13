// TC-2933: the owner renewal lease OpenKey signs when the renewal box is ticked, and the approval result
// that carries it. Uses the real WASM SIWE builder and a real owner signature; the node is a fake that
// only answers identity discovery.
import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { checkApprovalResultBinding } from '@tinycloud/share-envelope/links';
import { ApprovalResultService, type ApprovalRequestRecord, type ApprovalRequestStore } from '../services/approval-results';
import { strictSessionDid } from '../services/device-authorization';
import {
  MAX_LEASE_SECONDS,
  discoverRenewalNodeIdentity,
  parseRenewalChoice,
  prepareRenewalStage,
  signLease,
  type ApprovalResultRenewal,
} from '../services/renewal-lease';

const HOST = 'http://127.0.0.1:8000';
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const RENEWER_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const RENEWER_PUBLIC_KEY = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik';
const ORIGINAL_CID = 'bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yse';
const DAY = 86_400;

function node(keys: Record<string, unknown> = {}, info: Record<string, unknown> = { nodeId: NODE_DID }) {
  const asked: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    asked.push(url.href);
    const body = url.pathname === '/info' ? info : { nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0, ...keys };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { fetchImpl, asked };
}

async function approvedGrant(owner: { address: string; signMessage(message: string): Promise<string> }) {
  const space = `tinycloud:pkh:eip155:1:${owner.address}:agents`;
  const siwe = new SiweMessage({ domain: 'cli.tinycloud.xyz', address: owner.address, uri: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', version: '1', chainId: 1,
    nonce: 'qa123456', issuedAt: '2026-11-13T10:00:00.000Z', expirationTime: '2026-12-13T10:00:00.000Z' }).prepareMessage();
  return {
    delegationHeader: { Authorization: 'Bearer original-authorization' },
    delegationCid: ORIGINAL_CID,
    spaceId: space,
    hostActivated: true,
    siwe,
    signature: await owner.signMessage(siwe),
  };
}

describe('the owner renewal choice', () => {
  const signed = { version: 1 as const, leaseLifetimeSeconds: 182 * DAY };
  test('a request that did not ask for renewal takes no choice, and one that did needs one', () => {
    expect(parseRenewalChoice(undefined, undefined, true)).toBeNull();
    expect(() => parseRenewalChoice({ choice: 'finite' }, undefined, true)).toThrow('did not ask for renewal');
    expect(() => parseRenewalChoice(undefined, signed, true)).toThrow('renewal choice is required');
  });
  test('finite, or leased up to what the request signed and never past a year', () => {
    expect(parseRenewalChoice({ choice: 'finite' }, signed, true)).toEqual({ choice: 'finite' });
    expect(parseRenewalChoice({ choice: 'leased', leaseLifetimeSeconds: 182 * DAY }, signed, true)).toEqual({ choice: 'leased', leaseLifetimeSeconds: 182 * DAY });
    expect(() => parseRenewalChoice({ choice: 'leased', leaseLifetimeSeconds: 182 * DAY + 1 }, signed, true)).toThrow();
    expect(() => parseRenewalChoice({ choice: 'leased', leaseLifetimeSeconds: MAX_LEASE_SECONDS + 1 }, { version: 1, leaseLifetimeSeconds: MAX_LEASE_SECONDS + 1 }, true)).toThrow();
    expect(() => parseRenewalChoice({ choice: 'leased', leaseLifetimeSeconds: 0 }, signed, true)).toThrow();
    expect(() => parseRenewalChoice({ choice: 'leased', leaseLifetimeSeconds: 90 * DAY, extra: true }, signed, true)).toThrow();
  });
  test('while leases are off, a renewal request is finite and a lease is refused', () => {
    expect(parseRenewalChoice(undefined, signed, false)).toEqual({ choice: 'finite' });
    expect(parseRenewalChoice({ choice: 'finite' }, signed, false)).toEqual({ choice: 'finite' });
    expect(() => parseRenewalChoice({ choice: 'leased', leaseLifetimeSeconds: 90 * DAY }, signed, false)).toThrow('not available');
  });
});

describe('the renewer the lease names', () => {
  test('is the one the request node advertises at its own origin, matching its node id', async () => {
    const n = node();
    expect(await discoverRenewalNodeIdentity(HOST, n.fetchImpl)).toEqual({ nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 });
    expect(n.asked.map((url) => new URL(url).origin)).toEqual([HOST, HOST]);
  });
  test('is refused when the keys name another node, or the host is not a known node', async () => {
    await expect(discoverRenewalNodeIdentity(HOST, node({ nodeDid: RENEWER_DID }).fetchImpl)).rejects.toThrow('renewal identity is invalid');
    await expect(discoverRenewalNodeIdentity('https://node.example.test', node().fetchImpl)).rejects.toThrow('known TinyCloud nodes');
  });
  test('asks without following redirects and refuses an oversized answer', async () => {
    const inits: Array<RequestInit | undefined> = [];
    const big = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      inits.push(init);
      return new Response(JSON.stringify({ nodeId: NODE_DID, padding: 'x'.repeat(20_000) }), { status: 200 });
    }) as typeof fetch;
    await expect(discoverRenewalNodeIdentity(HOST, big)).rejects.toThrow('too large');
    expect(inits.every((init) => init?.redirect === 'error' && init.signal instanceof AbortSignal)).toBe(true);
  });
  test('on the production node, must be the pinned node DID, and nothing is asked without one', async () => {
    const saved = process.env.OPENKEY_RENEWAL_NODE_DID;
    try {
      const production = 'https://node.tinycloud.xyz';
      delete process.env.OPENKEY_RENEWAL_NODE_DID;
      const unpinned = node();
      await expect(discoverRenewalNodeIdentity(production, unpinned.fetchImpl)).rejects.toThrow('not configured');
      expect(unpinned.asked).toEqual([]);
      process.env.OPENKEY_RENEWAL_NODE_DID = RENEWER_DID;
      await expect(discoverRenewalNodeIdentity(production, node().fetchImpl)).rejects.toThrow('renewal identity is invalid');
      process.env.OPENKEY_RENEWAL_NODE_DID = NODE_DID;
      expect((await discoverRenewalNodeIdentity(production, node().fetchImpl)).nodeDid).toBe(NODE_DID);
      expect((await discoverRenewalNodeIdentity('https://tee.node.tinycloud.xyz', node().fetchImpl)).nodeDid).toBe(NODE_DID);
    } finally {
      if (saved === undefined) delete process.env.OPENKEY_RENEWAL_NODE_DID;
      else process.env.OPENKEY_RENEWAL_NODE_DID = saved;
    }
  });
});

describe('the lease OpenKey signs as the owner', () => {
  test('renews only the approved grant, for the renewer, until approval time plus the chosen lease', async () => {
    const owner = Wallet.createRandom();
    const now = new Date('2026-11-13T10:00:00.400Z');
    const stage = await prepareRenewalStage({ userId: 'user-1', host: HOST, leaseLifetimeSeconds: 90 * DAY, delegation: await approvedGrant(owner), now, fetchImpl: node().fetchImpl });
    const lease = new SiweMessage(stage.leaseSiwe);
    expect(lease.address).toBe(owner.address);
    expect(lease.uri).toBe(RENEWER_DID);
    expect(stage.approvedAt).toBe('2026-11-13T10:00:00.000Z');
    expect(lease.issuedAt).toBe(stage.approvedAt);
    expect(lease.expirationTime).toBe('2027-02-11T10:00:00.000Z');
    expect(stage.leaseExpiresAt).toBe(lease.expirationTime!);
    const recap = JSON.parse(Buffer.from(lease.resources!.at(-1)!.slice('urn:recap:'.length), 'base64url').toString());
    expect(recap.att).toEqual({ [`urn:cid:${ORIGINAL_CID}`]: { 'tinycloud.delegation/renew': [{}] } });
    expect(stage.originalAuthorization).toBe('original-authorization');
  });

  test('is refused when the grant never reached its node', async () => {
    const owner = Wallet.createRandom();
    const delegation = { ...await approvedGrant(owner), hostActivated: false };
    await expect(prepareRenewalStage({ userId: 'u', host: HOST, leaseLifetimeSeconds: DAY, delegation, now: new Date(), fetchImpl: node().fetchImpl })).rejects.toThrow('not registered');
  });

  test('the owner signature goes on the saved bytes; changed saved inputs are refused', async () => {
    const owner = Wallet.createRandom();
    const stage = await prepareRenewalStage({ userId: 'u', host: HOST, leaseLifetimeSeconds: 90 * DAY, delegation: await approvedGrant(owner), now: new Date(), fetchImpl: node().fetchImpl });
    const signed = signLease(stage, await owner.signMessage(stage.leaseSiwe));
    expect(signed.leaseCid).toMatch(/^baf/);
    expect(signed.leaseAuthorization).not.toMatch(/^Bearer/);
    expect(signLease(stage, await owner.signMessage(stage.leaseSiwe)).leaseCid).toBe(signed.leaseCid);
    expect(() => signLease({ ...stage, leaseExpiresAt: '2030-01-01T00:00:00.000Z' }, '0x00')).toThrow('Saved renewal lease changed');
  });
});

describe('the approval result for a request that asked for renewal', () => {
  async function fixture(renewalRequested: boolean) {
    const now = new Date('2026-11-13T10:00:00Z');
    const relay = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const relayJwk = await crypto.subtle.exportKey('jwk', relay.publicKey);
    const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string };
    const did = strictSessionDid(jwk);
    const owner = Wallet.createRandom();
    const record = {
      id: 'abcdefghijklmnopqrstuvwxyz', bodyCid: 'sealed-body-cid', issuer: did, createdAt: now, expiresAt: new Date(now.getTime() + 600_000),
      resultRef: null, encryptedResult: null, resultExpiresAt: null,
      request: { issuer: did, requestVersion: 1, targetDid: did, targetPublicJwk: jwk, nodeOrigin: HOST,
        permissions: [{ service: 'tinycloud.kv', space: 'qa', path: '', actions: ['tinycloud.kv/get'] }], grantLifetimeSeconds: 30 * DAY,
        resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x!, y: relayJwk.y! },
        ...(renewalRequested ? { purpose: 'standing', renewal: { version: 1, leaseLifetimeSeconds: 365 * DAY } } : {}) },
    } as unknown as ApprovalRequestRecord;
    const store = {
      async findById(id: string) { return id === record.id ? record : null; },
      async approve(_id: string, result: Partial<ApprovalRequestRecord>) { Object.assign(record, result); return true; },
    } as unknown as ApprovalRequestStore;
    const service = new ApprovalResultService(store, { apiOrigin: 'http://localhost:3001', retentionSeconds: 600, now: () => now });
    const siwe = new SiweMessage({ domain: 'cli.tinycloud.xyz', address: owner.address, uri: did, version: '1', chainId: 1,
      nonce: 'qa123456', issuedAt: now.toISOString(), expirationTime: new Date(now.getTime() + 30 * DAY * 1000).toISOString() }).prepareMessage();
    const delegation = { siwe, signature: await owner.signMessage(siwe), jwk, verificationMethod: did, ownerDid: `did:pkh:eip155:1:${owner.address}` };
    const body = { jwk, host: HOST, permissions: record.request.permissions };
    async function result(): Promise<Record<string, unknown>> {
      const envelope = JSON.parse(record.encryptedResult!);
      const ephemeral = await crypto.subtle.importKey('jwk', envelope.ephemeralPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
      const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: ephemeral }, relay.privateKey, 256);
      const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
      const context = new TextEncoder().encode(record.id);
      const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: context, info: new TextEncoder().encode('openkey-device-relay-v1') }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(envelope.nonce, 'base64url'), additionalData: context }, key, Buffer.from(envelope.ciphertext, 'base64url'));
      return JSON.parse(new TextDecoder().decode(plain));
    }
    return { service, record, delegation, body, result };
  }
  const renewal: ApprovalResultRenewal = {
    version: 1, approvedLeaseLifetimeSeconds: 90 * DAY, approvedAt: '2026-11-13T10:00:00.000Z',
    receipt: { originalCid: ORIGINAL_CID, leaseCid: 'bafkrlease', leaseAuthorization: 'lease-authorization', leaseExpiresAt: '2027-02-11T10:00:00.000Z', leaseGeneration: 1,
      nodeIdentity: { nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 } },
  };

  test('carries the lease when the owner left renewal on, in the shape the requester codec accepts', async () => {
    const f = await fixture(true);
    await f.service.approve(f.record.id, 'user-1', f.body, f.delegation, undefined, { choice: 'leased', renewal });
    const result = await f.result();
    expect(Object.keys(result).sort()).toEqual(['delegation', 'delegationExpiresAt', 'ownerDid', 'renewal', 'renewalChoice', 'requestDigest', 'requestId', 'requesterDid', 'resultVersion', 'targetDid']);
    const checked = checkApprovalResultBinding(result, {
      requestId: f.record.id, bodyCid: f.record.bodyCid, now: Date.parse('2026-11-13T10:00:00Z'),
      request: { issuer: f.record.request.issuer, targetDid: f.record.request.targetDid, renewal: f.record.request.renewal },
    });
    expect(checked.renewalChoice).toBe('leased');
    expect(checked.renewal).toEqual(renewal);
  });

  test('refuses lease metadata the requester codec would refuse, before saving anything', async () => {
    const f = await fixture(true);
    const tooLong = { ...renewal, receipt: { ...renewal.receipt, leaseExpiresAt: '2027-02-12T10:00:00.000Z' } };
    await expect(f.service.approve(f.record.id, 'user-1', f.body, f.delegation, undefined, { choice: 'leased', renewal: tooLong }))
      .rejects.toMatchObject({ code: 'invalid_delegation' });
    expect(f.record.encryptedResult).toBeNull();
  });

  test('says finite, with no lease, when the owner turned renewal off', async () => {
    const f = await fixture(true);
    await f.service.approve(f.record.id, 'user-1', f.body, f.delegation, undefined, { choice: 'finite' });
    const result = await f.result();
    const checked = checkApprovalResultBinding(result, {
      requestId: f.record.id, bodyCid: f.record.bodyCid, now: Date.parse('2026-11-13T10:00:00Z'),
      request: { issuer: f.record.request.issuer, targetDid: f.record.request.targetDid, renewal: f.record.request.renewal },
    });
    expect(checked.renewalChoice).toBe('finite');
    expect(result).not.toHaveProperty('renewal');
  });

  test('a renewal choice is refused for a request that did not ask, and required for one that did', async () => {
    const plain = await fixture(false);
    await expect(plain.service.approve(plain.record.id, 'u', plain.body, plain.delegation, undefined, { choice: 'finite' })).rejects.toMatchObject({ code: 'request_binding' });
    const asked = await fixture(true);
    await expect(asked.service.approve(asked.record.id, 'u', asked.body, asked.delegation)).rejects.toMatchObject({ code: 'request_binding' });
    expect(asked.record.encryptedResult).toBeNull();
  });
});
