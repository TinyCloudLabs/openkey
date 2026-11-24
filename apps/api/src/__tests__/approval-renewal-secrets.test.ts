// TC-3821: an approval request (/a/) that signed a renewal request, approved on a grant that reaches secrets. The
// preview refuses a leased choice without the owner's "Renew sensitive access?" confirm or with a window over 7 days,
// and saving the approval refuses the same before any lease is built, saved or sent to the node.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { createMiddleware } from 'hono/factory';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { Wallet } from 'ethers';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import type { ApprovalRequestRecord } from '../services/approval-results';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import type * as ApprovalRoutes from '../routes/approval-requests';
import { mockModules, replaceModules } from './mock-module';

type RouteModule = typeof ApprovalRoutes;

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied', '20261109_0001_approval_request_approving', '20261113_0001_approval_request_renewal']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const ID = 'abcdefghijklmnopqrstuvwxyz';
const DAY = 86_400;
const NODE = 'http://127.0.0.1:8125';
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const RENEWER_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const RENEWER_PUBLIC_KEY = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik';
const owner = Wallet.createRandom();
const space = `tinycloud:pkh:eip155:1:${owner.address}:default`;
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${owner.address}:default`;
const targetPublicJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: 'A'.repeat(43) };

let database: PGlite;
let client: PrismaClient;
let route: RouteModule;
let nodeCalls: string[] = [];
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
  route = await import('../routes/approval-requests?approval-renewal-secrets-test' as string) as RouteModule;
});
afterAll(async () => {
  globalThis.fetch = realFetch;
  if (savedFlag === undefined) delete process.env.OPENKEY_RENEWAL_LEASES;
  else process.env.OPENKEY_RENEWAL_LEASES = savedFlag;
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
  await client.approvalRequest.deleteMany();
  nodeCalls = [];
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (url.origin !== NODE) throw new Error(`unexpected ${url.href}`);
    nodeCalls.push(url.pathname);
    return Response.json(url.pathname === '/info' ? { nodeId: NODE_DID }
      : { nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 });
  }) as typeof fetch;
});

const store = () => createPrismaApprovalRequestStore(client);
const body = () => ({ approvalRequestId: ID, jwk: targetPublicJwk, host: NODE, permissions: [] });

/** A registered request that signed a one-year renewal request, admitted for approval. */
async function admitted() {
  await store().register({
    id: ID, bodyCid: 'sealed-body-cid', issuer: 'synthetic-requester',
    request: { targetDid: 'synthetic-requester', targetPublicJwk, nodeOrigin: NODE, permissions: [], grantLifetimeSeconds: 30 * DAY,
      renewal: { version: 1, leaseLifetimeSeconds: 365 * DAY } } as unknown as ApprovalRequestRecord['request'],
    expiresAt: new Date(Date.now() + 30 * 60_000), createdAt: new Date(),
    resultRef: null, encryptedResult: null, resultExpiresAt: null,
  });
  const request = body();
  await route.admitApprovalDelegation(request);
  return request;
}

/** The grant as the owner's approval signs it: `rawAbilities` beside a KV read, `windowSeconds` from now. */
function grantSiwe(rawAbilities: Record<string, string[]>, windowSeconds: number) {
  const issuedAt = Math.floor(Date.now() / 1000) * 1000;
  return prepareSession({
    address: owner.address, chainId: 1, domain: 'openkey.so', spaceId: space, jwk: targetPublicJwk,
    issuedAt: new Date(issuedAt).toISOString(), expirationTime: new Date(issuedAt + windowSeconds * 1000).toISOString(),
    abilities: { kv: { [space]: ['tinycloud.kv/get'] } },
    rawAbilities,
  } as unknown as Parameters<typeof prepareSession>[0]).siwe;
}
async function grant(rawAbilities: Record<string, string[]>, windowSeconds: number) {
  const siwe = grantSiwe(rawAbilities, windowSeconds);
  return { delegationHeader: { Authorization: 'Bearer original' }, delegationCid: 'bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yse',
    spaceId: space, hostActivated: true, siwe, signature: await owner.signMessage(siwe) };
}

const LEASED = { choice: 'leased' as const, leaseLifetimeSeconds: 90 * DAY };
const CONFIRMED = { ...LEASED, sensitiveConfirmed: true as const };
const SECRET_DECRYPT = { [`${network}/secrets/`]: ['tinycloud.encryption/decrypt'] };
const NETWORK_DECRYPT = { [network]: ['tinycloud.encryption/decrypt'] };

describe('the /a/ preview', () => {
  test('refuses a bare leased choice on secrets/ or network decrypt, and a confirmed one over 7 days', () => {
    for (const abilities of [SECRET_DECRYPT, NETWORK_DECRYPT]) {
      expect(() => route.checkApprovalLeaseGrant(grantSiwe(abilities, DAY), LEASED)).toThrow('needs your confirmation');
      expect(() => route.checkApprovalLeaseGrant(grantSiwe(abilities, 30 * DAY), CONFIRMED)).toThrow('at most 7 days');
      expect(() => route.checkApprovalLeaseGrant(grantSiwe(abilities, 7 * DAY), CONFIRMED)).not.toThrow();
      expect(() => route.checkApprovalLeaseGrant(grantSiwe(abilities, 30 * DAY), { choice: 'finite' })).not.toThrow();
    }
    expect(() => route.checkApprovalLeaseGrant(grantSiwe({}, 30 * DAY), LEASED)).not.toThrow();
  });
});

describe('saving an /a/ approval on a grant that reaches secrets', () => {
  for (const [name, abilities] of [['secrets/', SECRET_DECRYPT], ['network decrypt', NETWORK_DECRYPT]] as const) {
    test(`${name}: a lease without the owner confirm is refused; nothing is saved and the node is not asked`, async () => {
      const request = await admitted();
      await expect(route.saveApprovalDelegation(request, 'owner', await grant(abilities, DAY), { renewal: LEASED, host: NODE, sessionId: null }))
        .rejects.toMatchObject({ code: 'renewal_refused', status: 400 });
      const record = (await store().findById(ID))!;
      expect(record.renewal ?? null).toBeNull();
      expect(nodeCalls).toEqual([]);
    });
  }

  test('owner-confirmed with a 7-day window: the lease message is built for the chosen length', async () => {
    const request = await admitted();
    const answer = await route.saveApprovalDelegation(request, 'owner', await grant(SECRET_DECRYPT, 7 * DAY), { renewal: CONFIRMED, host: NODE, sessionId: null });
    expect(answer).toMatchObject({ renewalSignature: { leaseLifetimeSeconds: 90 * DAY } });
    expect((await store().findById(ID))!.renewal!.approvedLeaseLifetimeSeconds).toBe(90 * DAY);
  });

  test('owner-confirmed with a window over 7 days is refused', async () => {
    const request = await admitted();
    await expect(route.saveApprovalDelegation(request, 'owner', await grant(NETWORK_DECRYPT, 7 * DAY + 1), { renewal: CONFIRMED, host: NODE, sessionId: null }))
      .rejects.toMatchObject({ code: 'renewal_refused', status: 400 });
    expect(nodeCalls).toEqual([]);
  });

  test('an ordinary KV grant leases as before, with its 30-day window and no confirm', async () => {
    const request = await admitted();
    const answer = await route.saveApprovalDelegation(request, 'owner', await grant({}, 30 * DAY), { renewal: LEASED, host: NODE, sessionId: null });
    expect(answer).toMatchObject({ renewalSignature: { leaseLifetimeSeconds: 90 * DAY } });
  });
});
