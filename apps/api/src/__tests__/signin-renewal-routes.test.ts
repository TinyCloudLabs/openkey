// TC-2872: renewal at an app sign-in (the renewal checkbox on OpenKey's own sign-in window). The delegate routes run
// in-process with a managed key that really signs, the lease records on PGlite, and a loopback stand-in node that
// answers identity discovery and `/delegate`. What the node admits is checked by the real sdk-core admission code.
import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createMiddleware } from 'hono/factory';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { verifyMessage } from 'ethers';
import { SiweMessage } from 'siwe';
import { privateKeyToAccount } from 'viem/accounts';
import { completeSessionSetup, prepareSession } from '@tinycloud/node-sdk-wasm';
import * as signing from '../services/authorization-signing';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import { mockModules, replaceModules } from './mock-module';

const root = resolve(import.meta.dir, '../../../..');
const DAY = 86_400;
const NODE = 'http://127.0.0.1:8123';
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const RENEWER_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const RENEWER_PUBLIC_KEY = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik';
const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const stranger = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const owner = { id: 'owner_1', email: 'owner@example.test' };
const other = { id: 'other_1', email: 'other@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const space = `tinycloud:pkh:eip155:1:${account.address}:default`;
const managed = { id: 'managed_1', userId: owner.id, address: account.address, keyType: 'MANAGED', archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null };
const external = { ...managed, id: 'external_1', keyType: 'EXTERNAL', sealedBlob: null };
let currentUser = owner;
let currentKey: typeof managed | typeof external = managed;

let database: PGlite;
let client: PrismaClient;
const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id: string; userId: string } }) => where.id === currentKey.id && where.userId === currentUser.id ? currentKey : null),
    findMany: mock(async () => [currentKey]),
    findUnique: mock(async () => currentKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
  get renewalLease() { return client.renewalLease; },
  $transaction: (...args: Parameters<PrismaClient['$transaction']>) => client.$transaction(...args),
};
const signManagedMessage = mock(async (message: string) => account.signMessage({ message }));

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', currentUser);
      c.set('session', { id: `session_${currentUser.id}`, userId: currentUser.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
  // The lease reservation seals the signed lease with the auth secret.
  '../auth': () => ({ auth: { $context: Promise.resolve({ secretConfig: 'signin-renewal-test-secret-0123456789' }) } }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
    createWalletFromPrivateKey: () => ({ signMessage: ({ message }: { message: string }) => signManagedMessage(message) }),
    generatePrivateKey: () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    getAddressFromPrivateKey: () => account.address,
  }),
});

// The stand-in node: its identity, `/delegate` (a grant's activation, then the lease's admission) and `/revoke`.
// Each activation's and revocation's Authorization header is recorded in order; `onDelegate` may answer instead.
const realFetch = globalThis.fetch;
let activations: string[] = [];
let revocations: string[] = [];
let nodeCalls = 0;
let onDelegate: ((authorization: string, index: number) => Promise<Response | undefined>) | undefined;
function node() {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin !== NODE) throw new Error(`unexpected ${url.href}`);
    nodeCalls++;
    if (url.pathname === '/info') return Response.json({ nodeId: NODE_DID });
    if (url.pathname === '/.well-known/tinycloud/node-keys') {
      return Response.json({ nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 });
    }
    if (url.pathname === '/delegate' && init?.method === 'POST') {
      const authorization = String(new Headers(init.headers).get('Authorization'));
      activations.push(authorization);
      return await onDelegate?.(authorization, activations.length - 1) ?? Response.json({ activated: [], skipped: [] });
    }
    if (url.pathname === '/revoke' && init?.method === 'POST') {
      revocations.push(String(new Headers(init.headers).get('Authorization')));
      return new Response(null, { status: 200 });
    }
    throw new Error(`unexpected ${url.href}`);
  }) as typeof fetch;
}
function noNode() {
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => { throw new Error(`unexpected node call ${String(input)}`); }) as typeof fetch;
}

let router: typeof delegateRouter;
const savedFlag = process.env.OPENKEY_RENEWAL_LEASES;
beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  for (const user of [owner, other]) await client.user.create({ data: { id: user.id, email: user.email } });
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Loaded after the mocks above: the route captures its database client and TEE when it loads.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import('../routes/delegate?signin-renewal-routes' as string));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', currentUser);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: currentUser.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});
afterAll(async () => {
  globalThis.fetch = realFetch;
  if (savedFlag === undefined) delete process.env.OPENKEY_RENEWAL_LEASES;
  else process.env.OPENKEY_RENEWAL_LEASES = savedFlag;
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  signing._resetAuthorizationContextStoreForTests();
  process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
  currentUser = owner;
  currentKey = managed;
  activations = [];
  revocations = [];
  nodeCalls = 0;
  onDelegate = undefined;
  signManagedMessage.mockClear();
  node();
  await client.renewalLease.deleteMany();
});

async function post(path: string, body: unknown) {
  const response = await router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() as Record<string, any> };
}

function grantSiwe() {
  const now = Date.now();
  return prepareSession({
    address: account.address,
    chainId: 1,
    domain: 'openkey.so',
    issuedAt: new Date(now).toISOString(),
    expirationTime: new Date(now + 30 * DAY * 1000).toISOString(),
    spaceId: space,
    jwk,
    abilities: { kv: { [space]: ['tinycloud.kv/get', 'tinycloud.kv/put'] } } as unknown as Parameters<typeof prepareSession>[0]['abilities'],
  }).siwe;
}

const ASK = { version: 1, leaseLifetimeSeconds: 90 * DAY };

type Prepared = { authorizationContextToken: string; allowedActionIds: string[]; renewal?: unknown };

async function prepare(extra: Record<string, unknown> = { expiryChangeable: true, renewal: ASK }) {
  const prepared = await post('/authorize-sign-prepare', { keyId: currentKey.id, siwe: grantSiwe(), jwk, host: NODE, requestOrigin: 'https://openkey.so', ...extra });
  expect(prepared.status).toBe(200);
  return prepared.body as Prepared;
}

async function preview(p: Prepared, renewal?: unknown) {
  return post('/authorize-sign-preview', {
    authorizationContextToken: p.authorizationContextToken, selectedActionIds: p.allowedActionIds, ...(renewal === undefined ? {} : { renewal }),
  });
}

async function sign(p: Prepared, previewBody: Record<string, any>, extra: Record<string, unknown> = {}) {
  return post('/authorize-sign', {
    authorizationContextToken: p.authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken,
    selectedActionIds: p.allowedActionIds, protocolVersion: 1, ...extra,
  });
}

const LEASED = { choice: 'leased', leaseLifetimeSeconds: 90 * DAY };

/** The grant's own CID and the header that registers it, from the signed bytes and signature the response returned. */
function grantSetup(signed: Record<string, any>): { delegationCid: string; delegationHeader: { Authorization: string } } {
  return completeSessionSetup({
    siwe: signed.signedMessage, jwk, spaceId: space, verificationMethod: new SiweMessage(signed.signedMessage).uri, signature: signed.signature,
  } as Parameters<typeof completeSessionSetup>[0]);
}
function grantCid(signed: Record<string, any>): string {
  return grantSetup(signed).delegationCid;
}

/** The ReCap attenuation a signed SIWE carries. */
function attenuation(siwe: string): Record<string, Record<string, unknown>> {
  const recap = new SiweMessage(siwe).resources?.find((resource) => resource.startsWith('urn:recap:'));
  expect(recap).toBeDefined();
  return JSON.parse(Buffer.from(recap!.slice('urn:recap:'.length), 'base64url').toString('utf8')).att;
}

describe('while renewal leases are off', () => {
  test('a renewal ask changes nothing: no box, the same sign-in, no lease, no node call', async () => {
    delete process.env.OPENKEY_RENEWAL_LEASES;
    noNode();
    const asked = await prepare();
    expect(asked).not.toHaveProperty('renewal');
    const shown = await preview(asked);
    expect(shown.status).toBe(200);
    expect(shown.body).not.toHaveProperty('renewal');
    const signed = await sign(asked, shown.body);
    expect(signed.status).toBe(200);
    expect(Object.keys(signed.body).sort()).toEqual(['address', 'permissions', 'protocolVersion', 'selectedActionKeys', 'signature', 'signedMessage']);
    expect(signManagedMessage).toHaveBeenCalledTimes(1);
    expect(await client.renewalLease.count()).toBe(0);
  });

  test('a leased choice is refused at the preview, and the wallet step is refused outright', async () => {
    const offered = await prepare();
    delete process.env.OPENKEY_RENEWAL_LEASES;
    noNode();
    // Off since prepare: nothing asked for renewal, so any choice is a binding error.
    expect(await preview(await prepare(), LEASED)).toMatchObject({ status: 400, body: { code: 'request_binding' } });
    // Offered while on, then turned off: the choice is refused as unavailable.
    expect(await preview(offered, LEASED)).toMatchObject({ status: 400, body: { code: 'renewal_disabled' } });
    const step = await post('/authorize-sign-renewal', { renewalToken: 'okr_anything', signature: '0x00' });
    expect(step).toMatchObject({ status: 400, body: { code: 'renewal_disabled' } });
  });

  test('turned off after the owner chose renewal, signing refuses before anything is signed', async () => {
    const asked = await prepare();
    const shown = await preview(asked, LEASED);
    expect(shown.status).toBe(200);
    delete process.env.OPENKEY_RENEWAL_LEASES;
    const signed = await sign(asked, shown.body);
    expect(signed).toMatchObject({ status: 400, body: { code: 'renewal_disabled' } });
    expect(signed.body).not.toHaveProperty('signature');
    expect(signManagedMessage).not.toHaveBeenCalled();
  });
});

describe('the renewal ask at prepare', () => {
  test('is offered with its longest lease; an app that does not accept a changed expiry is refused', async () => {
    expect((await prepare()).renewal).toEqual({ leaseLifetimeSeconds: 90 * DAY });
    const refused = await post('/authorize-sign-prepare', { keyId: managed.id, siwe: grantSiwe(), jwk, host: NODE, requestOrigin: 'https://openkey.so', renewal: ASK });
    expect(refused).toMatchObject({ status: 400, body: { code: 'request_binding' } });
  });

  test('a malformed ask or one over a year is refused', async () => {
    for (const renewal of [{ version: 2, leaseLifetimeSeconds: DAY }, { version: 1, leaseLifetimeSeconds: 366 * DAY }, { version: 1, leaseLifetimeSeconds: 0 },
      { version: 1, leaseLifetimeSeconds: DAY, purpose: 'standing' }, { version: 1 }, null]) {
      const refused = await post('/authorize-sign-prepare', { keyId: managed.id, siwe: grantSiwe(), jwk, host: NODE, requestOrigin: 'https://openkey.so', expiryChangeable: true, renewal });
      expect(refused).toMatchObject({ status: 400, body: { code: 'invalid_renewal_request' } });
    }
  });
});

describe('a managed key with renewal turned on', () => {
  test('signs, registers the grant, then signs, records and admits a lease for exactly that grant', async () => {
    const asked = await prepare();
    const shown = await preview(asked, LEASED);
    expect(shown).toMatchObject({ status: 200, body: { renewal: LEASED } });
    const signed = await sign(asked, shown.body);
    expect(signed.status).toBe(200);
    expect(signed.body.renewalChoice).toBe('leased');
    expect(verifyMessage(signed.body.signedMessage, signed.body.signature).toLowerCase()).toBe(account.address.toLowerCase());

    // The grant reached its node first, then the lease.
    const cid = grantCid(signed.body);
    expect(activations).toHaveLength(2);
    const receipt = signed.body.renewal.receipt;
    expect(receipt.originalCid).toBe(cid);
    expect(activations[1]).toBe(receipt.leaseAuthorization);
    expect(signed.body.renewal).toMatchObject({ version: 1, approvedLeaseLifetimeSeconds: 90 * DAY });
    expect(Date.parse(receipt.leaseExpiresAt) - Date.parse(signed.body.renewal.approvedAt)).toBe(90 * DAY * 1000);

    // The lease the managed key signed: one ability, renew, on that grant's CID only, for the node's renewer.
    expect(signManagedMessage).toHaveBeenCalledTimes(2);
    const lease = signManagedMessage.mock.calls[1]![0];
    expect(new SiweMessage(lease).uri).toBe(RENEWER_DID);
    expect(new SiweMessage(lease).address).toBe(account.address);
    const att = attenuation(lease);
    expect(Object.keys(att)).toEqual([`urn:cid:${cid}`]);
    expect(Object.keys(att[`urn:cid:${cid}`]!)).toEqual(['tinycloud.delegation/renew']);

    // The owner's record: confirmed, no approval request, signed lease not kept, this session.
    const records = await client.renewalLease.findMany();
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      leaseCid: receipt.leaseCid, userId: owner.id, approvalRequestId: null, originalCid: cid, nodeOrigin: NODE,
      sessionId: `session_${owner.id}`, leaseAuthorization: null, revokedAt: null, grantSiwe: signed.body.signedMessage,
    });
    expect(records[0]!.admittedAt).not.toBeNull();
  });

  test('left unticked, the sign-in is finite: no lease and no node call', async () => {
    const asked = await prepare();
    const shown = await preview(asked, { choice: 'finite' });
    const signed = await sign(asked, shown.body);
    expect(signed.status).toBe(200);
    expect(signed.body.renewalChoice).toBe('finite');
    expect(signed.body).not.toHaveProperty('renewal');
    expect(nodeCalls).toBe(0);
    expect(await client.renewalLease.count()).toBe(0);
  });

  test('the choice is the one sealed with the preview: it cannot be added, changed or lengthened later', async () => {
    const asked = await prepare();
    expect((await preview(asked)).body.code).toBe('request_binding');
    expect((await preview(asked, { choice: 'leased', leaseLifetimeSeconds: 91 * DAY })).body.code).toBe('request_binding');
    const finite = await preview(asked, { choice: 'finite' });
    for (const renewal of [LEASED, { choice: 'leased', leaseLifetimeSeconds: DAY }]) {
      const signed = await sign(asked, finite.body, { renewal });
      expect(signed).toMatchObject({ status: 400, body: { code: 'request_binding' } });
    }
    expect(signManagedMessage).not.toHaveBeenCalled();
    // A sign-in that never asked for renewal takes no choice at all.
    const plain = await prepare({ expiryChangeable: true });
    expect(plain).not.toHaveProperty('renewal');
    expect((await preview(plain, { choice: 'finite' })).status).toBe(400);
  });

  test('a lease the node will not admit returns no signature', async () => {
    onDelegate = async (_authorization, index) => index === 1 ? new Response('refused', { status: 403 }) : undefined;
    const asked = await prepare();
    const signed = await sign(asked, (await preview(asked, LEASED)).body);
    expect(signed).toMatchObject({ status: 503, body: { code: 'renewal_failed', error: "OpenKey couldn't set up renewal. Nothing was approved. Try again." } });
    expect(signed.body).not.toHaveProperty('signature');
  });

  test('a lease stopped while it was being admitted is refused, and no signature is returned', async () => {
    // The owner stops it from Settings between the reservation and the confirmation.
    onDelegate = async (_authorization, index) => {
      if (index === 1) await client.renewalLease.updateMany({ data: { revokedAt: new Date() } });
      return undefined;
    };
    const asked = await prepare();
    const signed = await sign(asked, (await preview(asked, LEASED)).body);
    expect(signed).toMatchObject({ status: 409, body: { code: 'renewal_stopped' } });
    expect(signed.body).not.toHaveProperty('signature');
    expect((await client.renewalLease.findFirstOrThrow()).admittedAt).toBeNull();
  });

  test('a grant its node will not register gets no lease: nothing more is signed and no signature is returned', async () => {
    onDelegate = async (_authorization, index) => index === 0 ? new Response('refused', { status: 403 }) : undefined;
    const asked = await prepare();
    const signed = await sign(asked, (await preview(asked, LEASED)).body);
    expect(signed).toMatchObject({ status: 503, body: { code: 'renewal_failed' } });
    expect(signed.body).not.toHaveProperty('signature');
    // Only the grant was signed: the lease is signed after the node holds the grant, never before.
    expect(signManagedMessage).toHaveBeenCalledTimes(1);
    expect(activations).toHaveLength(1);
    expect(await client.renewalLease.count()).toBe(0);
  });

  test('an admission whose answer was lost is stopped before the failure is returned', async () => {
    // The node stores the lease, but its answer never arrives.
    onDelegate = async (_authorization, index) => index === 1 ? new Response('unavailable', { status: 503 }) : undefined;
    const asked = await prepare();
    const signed = await sign(asked, (await preview(asked, LEASED)).body);
    expect(signed).toMatchObject({ status: 503, body: { code: 'renewal_failed' } });
    expect(signed.body).not.toHaveProperty('signature');
    expect(revocations).toHaveLength(1);
    const record = await client.renewalLease.findFirstOrThrow();
    expect(record.revokedAt).not.toBeNull();
    expect(record.admittedAt).toBeNull();
  });
});

describe('an external wallet with renewal turned on', () => {
  async function signedGrant() {
    currentKey = external;
    const asked = await prepare();
    const shown = await preview(asked, LEASED);
    const signed = await sign(asked, shown.body, { externalSignature: await account.signMessage({ message: shown.body.signedMessage }) });
    expect(signed.status).toBe(200);
    return signed.body;
  }

  test('gets the lease to sign after the grant; the lease is admitted only with the owner\'s signature on it', async () => {
    const grant = await signedGrant();
    expect(grant.renewalChoice).toBe('leased');
    expect(grant).not.toHaveProperty('renewal');
    // The node already holds the grant, and only the grant, when the lease is handed out to sign.
    expect(activations).toEqual([grantSetup(grant).delegationHeader.Authorization]);
    const { message, leaseLifetimeSeconds, renewalToken } = grant.renewalSignature;
    expect(leaseLifetimeSeconds).toBe(90 * DAY);
    const cid = grantCid(grant);
    expect(Object.keys(attenuation(message))).toEqual([`urn:cid:${cid}`]);
    expect(await client.renewalLease.count()).toBe(0);

    const done = await post('/authorize-sign-renewal', { renewalToken, signature: await account.signMessage({ message }) });
    expect(done.status).toBe(200);
    expect(done.body).toMatchObject({ renewalChoice: 'leased', renewal: { version: 1, receipt: { originalCid: cid } } });
    expect(activations.at(-1)).toBe(done.body.renewal.receipt.leaseAuthorization);
    const record = await client.renewalLease.findFirstOrThrow();
    expect(record).toMatchObject({ approvalRequestId: null, userId: owner.id, originalCid: cid, leaseAuthorization: null });
    expect(record.admittedAt).not.toBeNull();
    // Taken once.
    expect((await post('/authorize-sign-renewal', { renewalToken, signature: await account.signMessage({ message }) })).status).toBe(410);
  });

  test('another wallet\'s signature, or another account, sets nothing up', async () => {
    const grant = await signedGrant();
    const { message, renewalToken } = grant.renewalSignature;
    currentUser = other;
    expect((await post('/authorize-sign-renewal', { renewalToken, signature: await account.signMessage({ message }) })).status).toBe(410);
    currentUser = owner;
    const wrong = await post('/authorize-sign-renewal', { renewalToken, signature: await stranger.signMessage({ message }) });
    expect(wrong).toMatchObject({ status: 400, body: { code: 'invalid_signature' } });
    expect(await client.renewalLease.count()).toBe(0);
  });

  test('a grant its node will not register gets no lease to sign', async () => {
    currentKey = external;
    onDelegate = async (_authorization, index) => index === 0 ? new Response('refused', { status: 403 }) : undefined;
    const asked = await prepare();
    const shown = await preview(asked, LEASED);
    const signed = await sign(asked, shown.body, { externalSignature: await account.signMessage({ message: shown.body.signedMessage }) });
    expect(signed).toMatchObject({ status: 503, body: { code: 'renewal_failed' } });
    expect(signed.body).not.toHaveProperty('signature');
    expect(signed.body).not.toHaveProperty('renewalSignature');
    expect(await client.renewalLease.count()).toBe(0);
  });
});
