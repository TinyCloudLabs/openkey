// TC-2933: a real signed approval link that asks for renewal loads through the pinned codec, and saving an
// approval honours only the renewal choice the owner approved now: an unsigned saved lease step is rebuilt from
// it, and an already-signed lease is collected only for the same length, never as a silent leased result.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { createApprovalRequest, signerFromJwk } from '@tinycloud/share-envelope/links';
import type { ApprovalRequestRecord } from '../services/approval-results';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import type { RenewalStage } from '../services/renewal-lease';
import { mockModules, replaceModules } from './mock-module';

type RouteModule = typeof import('../routes/approval-requests');

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied', '20261109_0001_approval_request_approving', '20261113_0001_approval_request_renewal']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const ID = 'abcdefghijklmnopqrstuvwxyz';
const DAY = 86_400;
const NODE = 'http://127.0.0.1:8123';
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const RENEWER_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const RENEWER_PUBLIC_KEY = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik';

let database: PGlite;
let client: PrismaClient;
let route: RouteModule;
const realFetch = globalThis.fetch;
const savedFlag = process.env.OPENKEY_RENEWAL_LEASES;

replaceModules({
  '../middleware/session': () => ({ requireSession: createMiddleware(async (_c, next) => { await next(); }) }),
});
await mockModules({ '@openkey/db': () => ({ createPrismaClient: () => client }) });

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  for (const migration of MIGRATIONS) await database.exec(await readFile(migration, 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  // Static import cannot work: the route captures the database client when it loads.
  route = await import('../routes/approval-requests?approval-renewal-save-test' as string) as RouteModule;
});
afterAll(async () => {
  globalThis.fetch = realFetch;
  if (savedFlag === undefined) delete process.env.OPENKEY_RENEWAL_LEASES;
  else process.env.OPENKEY_RENEWAL_LEASES = savedFlag;
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  globalThis.fetch = realFetch;
  process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
  await client.approvalRequest.deleteMany();
});

const canonical = (value: unknown): string => Array.isArray(value)
  ? `[${value.map(canonical).join(',')}]`
  : value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`
    : JSON.stringify(value);

describe('a real signed approval link that asks for renewal', () => {
  test('loads through the pinned codec with its purpose and renewal, and says whether renewal is offered', async () => {
    const issuerPair = generateKeyPairSync('ed25519');
    const issuerJwk = issuerPair.privateKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string };
    const issuer = signerFromJwk(issuerJwk);
    const relay = await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])).publicKey);
    // The links service: stores the one record it is given and serves it back, as the Worker does.
    let stored: { header: unknown; signature: unknown; body: string } | null = null;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.origin !== 'https://api.tinycloud.xyz') return realFetch(input, init);
      if (url.pathname === '/v1/links' && init?.method === 'POST') {
        stored = JSON.parse(String(init.body));
        return Response.json({ id: ID, expiresAt: (stored!.header as { expiresAt: string }).expiresAt }, { status: 201 });
      }
      if (url.pathname === `/v1/links/${ID}` && stored) {
        const { header, signature, body } = stored;
        return new Response(Buffer.from(body, 'base64url'), { status: 200, headers: {
          'content-type': 'application/octet-stream', 'x-link-record': Buffer.from(canonical({ header, signature })).toString('base64url'),
        } });
      }
      return new Response('{"error":"not_found"}', { status: 404 });
    }) as typeof fetch;
    const created = await createApprovalRequest({
      issuerKey: issuer, apiOrigin: 'https://api.tinycloud.xyz', openkeyOrigin: 'https://openkey.so',
      request: {
        issuer: issuer.did, requestVersion: 1, targetDid: issuer.did,
        targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: issuerJwk.x }, nodeOrigin: 'https://node.tinycloud.xyz',
        permissions: [{ service: 'tinycloud.kv', space: 'qa', path: '', actions: ['tinycloud.kv/get'] }],
        grantLifetimeSeconds: 30 * DAY, resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relay.x!, y: relay.y! },
        purpose: 'standing', renewal: { version: 1, leaseLifetimeSeconds: 365 * DAY },
      },
    });
    const load = async () => route.approvalRequestRouter.request(`/approval-requests/${ID}/load`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ reference: created.link.slice('https://openkey.so'.length) }),
    });
    const on = await load();
    expect(on.status).toBe(200);
    const loaded = await on.json() as { request: Record<string, unknown>; renewalAvailable: boolean };
    expect(loaded.request.purpose).toBe('standing');
    expect(loaded.request.renewal).toEqual({ version: 1, leaseLifetimeSeconds: 365 * DAY });
    expect(loaded.renewalAvailable).toBe(true);
    delete process.env.OPENKEY_RENEWAL_LEASES;
    expect((await (await load()).json() as { renewalAvailable: boolean }).renewalAvailable).toBe(false);
  });
});

describe('saving an approval that asked for renewal', () => {
  const owner = Wallet.createRandom();
  const store = () => createPrismaApprovalRequestStore(client);
  const targetPublicJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: 'A'.repeat(43) };
  const register = () => store().register({
    id: ID, bodyCid: 'sealed-body-cid', issuer: 'synthetic-requester',
    request: { targetDid: 'synthetic-requester', targetPublicJwk, nodeOrigin: NODE, permissions: [], grantLifetimeSeconds: 30 * DAY,
      renewal: { version: 1, leaseLifetimeSeconds: 365 * DAY } } as unknown as ApprovalRequestRecord['request'],
    expiresAt: new Date(Date.now() + 30 * 60_000), createdAt: new Date(),
    resultRef: null, encryptedResult: null, resultExpiresAt: null,
  });
  const body = () => ({ approvalRequestId: ID, jwk: targetPublicJwk, host: NODE, permissions: [] });
  async function grant() {
    const siwe = new SiweMessage({ domain: 'cli.tinycloud.xyz', address: owner.address, uri: NODE_DID, version: '1', chainId: 1,
      nonce: 'qa123456', issuedAt: new Date().toISOString(), expirationTime: new Date(Date.now() + 30 * DAY * 1000).toISOString() }).prepareMessage();
    return { delegationHeader: { Authorization: 'Bearer original' }, delegationCid: 'bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yse',
      spaceId: `tinycloud:pkh:eip155:1:${owner.address}:agents`, hostActivated: true, siwe, signature: await owner.signMessage(siwe) };
  }
  const saved = (extra: Partial<RenewalStage>): RenewalStage => ({
    version: 1, userId: 'owner', approvedAt: new Date().toISOString(), approvedLeaseLifetimeSeconds: 90 * DAY,
    leaseExpiresAt: new Date(Date.now() + 90 * DAY * 1000).toISOString(),
    nodeIdentity: { nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 },
    delegation: {}, originalCid: 'bafy-original', originalAuthorization: 'original', ownerAddress: owner.address, chainId: 1,
    spaceId: 'space', leaseNonce: 'nonce', leaseSiwe: 'older lease message', ...extra,
  });
  async function admittedWith(stage: RenewalStage) {
    await register();
    const request = body();
    await route.admitApprovalDelegation(request);
    const marker = (await store().findById(ID))!.approvingAt!;
    await store().saveRenewal(ID, stage, marker);
    return request;
  }
  function node() {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = new URL(String(input));
      if (url.origin !== NODE) throw new Error(`unexpected ${url.href}`);
      return Response.json(url.pathname === '/info' ? { nodeId: NODE_DID }
        : { nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 });
    }) as typeof fetch;
  }

  test('an unsigned saved lease step is rebuilt from the length approved now, never reused', async () => {
    node();
    const request = await admittedWith(saved({}));
    const answer = await route.saveApprovalDelegation(request, 'owner', await grant(), { renewal: { choice: 'leased', leaseLifetimeSeconds: DAY }, host: NODE });
    expect(answer).toMatchObject({ renewalSignature: { leaseLifetimeSeconds: DAY } });
    const stage = (await store().findById(ID))!.renewal!;
    expect(stage.approvedLeaseLifetimeSeconds).toBe(DAY);
    expect(new SiweMessage(stage.leaseSiwe).expirationTime).toBe(stage.leaseExpiresAt);
    expect(Date.parse(stage.leaseExpiresAt) - Date.parse(stage.approvedAt)).toBe(DAY * 1000);
  });

  test('an already-signed lease is never completed for a finite or different choice: it is a conflict', async () => {
    for (const renewal of [{ choice: 'finite' as const }, { choice: 'leased' as const, leaseLifetimeSeconds: DAY }]) {
      await client.approvalRequest.deleteMany();
      const request = await admittedWith(saved({ leaseAuthorization: 'signed-lease', leaseCid: 'bafy-lease' }));
      await expect(route.saveApprovalDelegation(request, 'owner', await grant(), { renewal, host: NODE }))
        .rejects.toMatchObject({ code: 'renewal_already_signed', status: 409, extra: { leaseLifetimeSeconds: 90 * DAY } });
      const record = (await store().findById(ID))!;
      expect(record.resultRef).toBeNull();
      expect(record.renewal?.leaseAuthorization).toBe('signed-lease');
    }
  });

  test('another account cannot collect a lease this owner signed', async () => {
    const request = await admittedWith(saved({ leaseAuthorization: 'signed-lease', leaseCid: 'bafy-lease' }));
    await expect(route.saveApprovalDelegation(request, 'someone-else', await grant(), { renewal: { choice: 'leased', leaseLifetimeSeconds: 90 * DAY }, host: NODE }))
      .rejects.toMatchObject({ code: 'request_binding', status: 409 });
  });

  test('the lease is only for the node the grant was approved for', async () => {
    node();
    const request = await admittedWith(saved({}));
    await expect(route.saveApprovalDelegation(request, 'owner', await grant(), { renewal: { choice: 'leased', leaseLifetimeSeconds: DAY }, host: 'http://127.0.0.1:9999' }))
      .rejects.toMatchObject({ code: 'request_binding', status: 400 });
  });

  test('a deny clears the saved lease step', async () => {
    await register();
    const request = body();
    await route.admitApprovalDelegation(request);
    const marker = (await store().findById(ID))!.approvingAt!;
    await store().saveRenewal(ID, saved({}), marker);
    await store().release(ID, marker);
    expect(await store().deny(ID, new Date())).toBe(true);
    expect((await store().findById(ID))!.renewal).toBeNull();
  });
});
