// TC-2789 (Naomi's ruling c″): on the managed path a save that fails after activation revokes the grant (delegate.ts).
// When the failure is the node refusing the signed renewal lease, the saved lease step still names that revoked grant,
// so the retry is refused (start a new request) and never hands the revoked grant over. The lease reservation is kept
// as it was (TC-2946).
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import type { ApprovalRequestRecord } from '../services/approval-results';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import { mockModules, replaceModules } from './mock-module';

type RouteModule = typeof import('../routes/approval-requests');

const root = resolve(import.meta.dir, '../../../..');
const ID = 'abcdefghijklmnopqrstuvwxyz';
const DAY = 86_400;
const NODE = 'http://127.0.0.1:8123';
const NODE_IDENTITY = {
  nodeDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  renewerDid: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
  renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik',
  renewerEpoch: 0,
};
const REVOKED_CID = 'bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yse';
const RETRY_CID = 'bafyreihzwbn4dmeq5pbs3xvvgfvzrlrbbrcpjx7nsmhkiwr2xxlgmqm6oe';

let database: PGlite;
let client: PrismaClient;
let route: RouteModule;
const realFetch = globalThis.fetch;
const savedFlag = process.env.OPENKEY_RENEWAL_LEASES;

replaceModules({
  '../middleware/session': () => ({ requireSession: async (_c: unknown, next: () => Promise<void>) => { await next(); } }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => client }),
  // The reservation is the real one; only its encryption key (Better Auth's secret) is replaced.
  '../services/renewal-lease-revocation': (actual) => ({
    reserveRenewalLease: (db: unknown, input: unknown) => actual.reserveRenewalLease(db, input, { seal: async (data: string) => `sealed:${data}` }),
    reservedLeaseAuthorization: (db: unknown, userId: string, leaseCid: string) =>
      actual.reservedLeaseAuthorization(db, userId, leaseCid, { open: async (data: string) => data.replace(/^sealed:/, '') }),
  }),
});

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  // Static import cannot work: the route captures the database client when it loads.
  route = await import('../routes/approval-requests?approval-renewal-revoked-retry-test' as string) as RouteModule;
  process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
});
afterAll(async () => {
  globalThis.fetch = realFetch;
  if (savedFlag === undefined) delete process.env.OPENKEY_RENEWAL_LEASES;
  else process.env.OPENKEY_RENEWAL_LEASES = savedFlag;
  await client.$disconnect();
  await database.close();
});

test('a managed retry after the node refused the lease is refused, and the revoked grant never appears', async () => {
  const owner = Wallet.createRandom();
  const store = createPrismaApprovalRequestStore(client);
  const targetPublicJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: 'A'.repeat(43) };
  await client.user.create({ data: { id: 'owner', email: 'owner@example.test', name: 'owner', emailVerified: true } });
  await store.register({
    id: ID, bodyCid: 'sealed-body-cid', issuer: 'synthetic-requester',
    request: { targetDid: 'synthetic-requester', targetPublicJwk, nodeOrigin: NODE, permissions: [], grantLifetimeSeconds: 30 * DAY,
      renewal: { version: 1, leaseLifetimeSeconds: 365 * DAY } } as unknown as ApprovalRequestRecord['request'],
    expiresAt: new Date(Date.now() + 30 * 60_000), createdAt: new Date(),
    resultRef: null, encryptedResult: null, resultExpiresAt: null,
  });
  const grant = async (delegationCid: string) => {
    const siwe = new SiweMessage({ domain: 'cli.tinycloud.xyz', address: owner.address, uri: NODE_IDENTITY.nodeDid, version: '1', chainId: 1,
      nonce: 'qa123456', issuedAt: new Date().toISOString(), expirationTime: new Date(Date.now() + 30 * DAY * 1000).toISOString() }).prepareMessage();
    return { delegationHeader: { Authorization: `Bearer grant-${delegationCid}` }, delegationCid,
      spaceId: `tinycloud:pkh:eip155:1:${owner.address}:agents`, hostActivated: true, siwe, signature: await owner.signMessage(siwe) };
  };
  const options = {
    renewal: { choice: 'leased' as const, leaseLifetimeSeconds: 365 * DAY }, host: NODE, sessionId: null,
    signOwner: (message: string) => owner.signMessage(message),
  };
  // The node answers its identity but refuses to admit the lease. Every node call is recorded.
  const nodeCalls: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    if (url.origin !== NODE) throw new Error(`unexpected ${url.href}`);
    nodeCalls.push(url.pathname);
    if (url.pathname === '/info') return Response.json({ nodeId: NODE_IDENTITY.nodeDid });
    if (url.pathname === '/.well-known/tinycloud/node-keys') return Response.json(NODE_IDENTITY);
    return Response.json({ error: 'unavailable' }, { status: 503 });
  }) as typeof fetch;
  const answers: unknown[] = [];
  const outcome = (promise: Promise<unknown>) => promise.then(
    (value) => { answers.push(value); return { value }; },
    (error: { message: string; code?: string; status?: number; extra?: unknown }) => {
      const answer = { error: error.message, code: error.code, status: error.status, extra: error.extra };
      answers.push(answer);
      return answer;
    },
  );

  // First attempt: the owner's lease is signed and saved, then the node refuses to admit it.
  const first = { approvalRequestId: ID, jwk: targetPublicJwk, host: NODE, permissions: [] };
  await route.admitApprovalDelegation(first);
  const failed = await outcome(route.saveApprovalDelegation(first, 'owner', await grant(REVOKED_CID), options));
  expect(failed).toMatchObject({ code: 'renewal_failed' });
  const stage = (await store.findById(ID))!.renewal!;
  expect(stage.leaseCid).toBeDefined();
  expect(stage.delegation.delegationCid).toBe(REVOKED_CID);
  const reservation = await client.renewalLease.findUniqueOrThrow({ where: { leaseCid: stage.leaseCid! } });
  // delegate.ts revokes the grant here and gives the admission back.
  await route.releaseApprovalDelegation(first);

  // Retry with a fresh grant: refused before any node call, nothing is saved, and the revoked grant is never returned.
  nodeCalls.length = 0;
  const retry = { approvalRequestId: ID, jwk: targetPublicJwk, host: NODE, permissions: [] };
  await route.admitApprovalDelegation(retry);
  const refused = await outcome(route.saveApprovalDelegation(retry, 'owner', await grant(RETRY_CID), options));
  expect(refused).toEqual({ error: 'Renewal failed. Start a new request.', code: 'renewal_failed', status: 409, extra: undefined });
  expect(nodeCalls).toEqual([]);
  const record = (await store.findById(ID))!;
  expect([record.resultRef, record.encryptedResult]).toEqual([null, null]);
  for (const answer of answers) expect(JSON.stringify(answer)).not.toContain(REVOKED_CID);
  // The saved step and the lease reservation are left as they were.
  expect(record.renewal).toEqual(stage);
  expect(await client.renewalLease.findUniqueOrThrow({ where: { leaseCid: stage.leaseCid! } })).toEqual(reservation);
});
