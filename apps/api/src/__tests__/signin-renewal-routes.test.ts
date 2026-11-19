// TC-2872: renewal at an app sign-in (the renewal checkbox on OpenKey's own sign-in window). The delegate routes run
// in-process with a managed key that really signs, and a loopback stand-in node. OpenKey only asks the node who its
// renewer is, and records each lease it signs (so every stop can revoke it) before returning it; any other
// lease-table access or node write fails the test. The returned lease is then admitted the way the app does it, by
// the real sdk-core admission code. Stopping recorded sign-in leases: signin-renewal-lease-stop.integration.test.ts.
import { beforeAll, afterAll, beforeEach, describe, expect, mock, spyOn, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { verifyMessage } from 'ethers';
import { SiweMessage } from 'siwe';
import { privateKeyToAccount } from 'viem/accounts';
import { completeSessionSetup, prepareSession } from '@tinycloud/node-sdk-wasm';
import { admitOwnerRenewalLease } from '@tinycloud/sdk-core/delegations/renewal';
import * as signing from '../services/authorization-signing';
import { strictSessionDid } from '../services/device-authorization';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import { mockModules, replaceModules } from './mock-module';

const DAY = 86_400;
const NODE = 'http://127.0.0.1:8123';
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const RENEWER_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const RENEWER_PUBLIC_KEY = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik';
const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const stranger = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const owner = { id: 'owner_1', email: 'owner@example.test' };
const other = { id: 'other_1', email: 'other@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } as const;
const space = `tinycloud:pkh:eip155:1:${account.address}:default`;
const managed = { id: 'managed_1', userId: owner.id, address: account.address, keyType: 'MANAGED', archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null };
const external = { ...managed, id: 'external_1', keyType: 'EXTERNAL', sealedBlob: null };
let currentUser = owner;
let currentKey: typeof managed | typeof external = managed;

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id: string; userId: string } }) => where.id === currentKey.id && where.userId === currentUser.id ? currentKey : null),
    findMany: mock(async () => [currentKey]),
    findUnique: mock(async () => currentKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
  // A sign-in records its lease only through `reserveRenewalLease` (mocked below), never directly.
  get renewalLease(): never { throw new Error('a sign-in touched the renewal lease table'); },
  $transaction: () => { throw new Error('a sign-in opened a database transaction'); },
};
const signManagedMessage = mock(async (message: string) => account.signMessage({ message }));
type Reservation = { approvalRequestId: string | null; userId: string; sessionId: string | null; nodeOrigin: string; stage: { leaseCid: string; leaseAuthorization: string } };
const reserveRenewalLease = mock(async (_db: unknown, _input: Reservation): Promise<void> => undefined);
const reservations = () => reserveRenewalLease.mock.calls.map(([, input]) => input);

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', currentUser);
      c.set('session', { id: `session_${currentUser.id}`, userId: currentUser.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
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
  '../services/renewal-lease-revocation': () => ({ reserveRenewalLease }),
});

// The stand-in node. OpenKey may only read its identity; `/delegate` answers only while the app admits a lease
// (`appAdmitting`). Every call is recorded as `METHOD path`.
const realFetch = globalThis.fetch;
let nodeCalls: string[] = [];
let admitted: string[] = [];
let identityAnswer: (() => Response) | undefined;
let appAdmitting = false;
function node() {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin !== NODE) throw new Error(`unexpected ${url.href}`);
    nodeCalls.push(`${init?.method ?? 'GET'} ${url.pathname}`);
    if (url.pathname === '/info') return identityAnswer?.() ?? Response.json({ nodeId: NODE_DID });
    if (url.pathname === '/.well-known/tinycloud/node-keys') {
      return Response.json({ nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 });
    }
    if (appAdmitting && url.pathname === '/delegate' && init?.method === 'POST') {
      admitted.push(String(new Headers(init.headers).get('Authorization')));
      return Response.json({ activated: [], skipped: [] });
    }
    throw new Error(`unexpected node call ${init?.method ?? 'GET'} ${url.href}`);
  }) as typeof fetch;
}
function noNode() {
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => { throw new Error(`unexpected node call ${String(input)}`); }) as typeof fetch;
}

let router: typeof delegateRouter;
const savedFlag = process.env.OPENKEY_RENEWAL_LEASES;
beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Loaded after the mocks above: the route captures its database client and TEE when it loads.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import('../routes/delegate?signin-renewal-routes' as string));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', currentUser);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: currentUser.id });
    c.set('session', { id: `session_${currentUser.id}`, userId: currentUser.id, expiresAt: new Date(Date.now() + 60_000) });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});
afterAll(() => {
  globalThis.fetch = realFetch;
  if (savedFlag === undefined) delete process.env.OPENKEY_RENEWAL_LEASES;
  else process.env.OPENKEY_RENEWAL_LEASES = savedFlag;
});
beforeEach(() => {
  signing._resetAuthorizationContextStoreForTests();
  process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
  currentUser = owner;
  currentKey = managed;
  nodeCalls = [];
  admitted = [];
  identityAnswer = undefined;
  appAdmitting = false;
  signManagedMessage.mockClear();
  reserveRenewalLease.mockClear();
  reserveRenewalLease.mockImplementation(async () => undefined);
  node();
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
const IDENTITY_READS = ['GET /.well-known/tinycloud/node-keys', 'GET /info'];

/** The grant's own CID and the header that registers it, from the signed bytes and signature the response returned. */
function grantSetup(signed: Record<string, any>): { delegationCid: string; delegationHeader: { Authorization: string } } {
  return completeSessionSetup({
    siwe: signed.signedMessage, jwk, spaceId: space, verificationMethod: new SiweMessage(signed.signedMessage).uri, signature: signed.signature,
  } as Parameters<typeof completeSessionSetup>[0]);
}

/** The ReCap attenuation a signed SIWE carries. */
function attenuation(siwe: string): Record<string, Record<string, unknown>> {
  const recap = new SiweMessage(siwe).resources?.find((resource) => resource.startsWith('urn:recap:'));
  expect(recap).toBeDefined();
  return JSON.parse(Buffer.from(recap!.slice('urn:recap:'.length), 'base64url').toString('utf8')).att;
}

/** What the app does with a leased sign-in: has the grant's node admit the returned lease. */
async function appAdmits(signed: Record<string, any>, renewal: Record<string, any>) {
  appAdmitting = true;
  const grant = grantSetup(signed);
  return admitOwnerRenewalLease({
    host: NODE,
    originalAuthorization: grant.delegationHeader.Authorization.replace(/^Bearer\s+/i, ''),
    originalCid: grant.delegationCid,
    ownerDid: `did:pkh:eip155:1:${account.address}`,
    agentDid: strictSessionDid(jwk),
    spaceId: space,
    nodeIdentity: renewal.receipt.nodeIdentity,
    leaseAuthorization: renewal.receipt.leaseAuthorization,
    leaseCid: renewal.receipt.leaseCid,
    leaseExpiresAt: renewal.receipt.leaseExpiresAt,
  });
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
    expect(nodeCalls).toEqual([]);
    expect(reserveRenewalLease).not.toHaveBeenCalled();
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
  test('returns the grant with a signed lease for exactly that grant; OpenKey only reads the node identity', async () => {
    const asked = await prepare();
    const shown = await preview(asked, LEASED);
    expect(shown).toMatchObject({ status: 200, body: { renewal: LEASED } });
    const signed = await sign(asked, shown.body);
    expect(signed.status).toBe(200);
    expect(signed.body.renewalChoice).toBe('leased');
    expect(verifyMessage(signed.body.signedMessage, signed.body.signature).toLowerCase()).toBe(account.address.toLowerCase());
    expect(nodeCalls.sort()).toEqual(IDENTITY_READS);

    // The lease the managed key signed: one ability, renew, on that grant's CID only, for the node's renewer.
    const cid = grantSetup(signed.body).delegationCid;
    expect(signManagedMessage).toHaveBeenCalledTimes(2);
    const lease = signManagedMessage.mock.calls[1]![0];
    expect(new SiweMessage(lease).uri).toBe(RENEWER_DID);
    expect(new SiweMessage(lease).address).toBe(account.address);
    const att = attenuation(lease);
    expect(Object.keys(att)).toEqual([`urn:cid:${cid}`]);
    expect(Object.keys(att[`urn:cid:${cid}`]!)).toEqual(['tinycloud.delegation/renew']);

    const renewal = signed.body.renewal;
    expect(renewal).toMatchObject({ version: 1, approvedLeaseLifetimeSeconds: 90 * DAY, receipt: { originalCid: cid, leaseGeneration: 1 } });
    expect(renewal.receipt.nodeIdentity).toMatchObject({ nodeDid: NODE_DID, renewerDid: RENEWER_DID });
    expect(Date.parse(renewal.receipt.leaseExpiresAt) - Date.parse(renewal.approvedAt)).toBe(90 * DAY * 1000);
  });

  test('the app can have the node admit the returned lease, and gets the same lease back', async () => {
    const asked = await prepare();
    const signed = await sign(asked, (await preview(asked, LEASED)).body);
    const receipt = await appAdmits(signed.body, signed.body.renewal);
    expect(admitted).toEqual([signed.body.renewal.receipt.leaseAuthorization]);
    expect(receipt).toEqual(signed.body.renewal.receipt);
  });

  test('records the lease for its owner and signing session before returning it, with no approval request', async () => {
    const asked = await prepare();
    let returned = false;
    reserveRenewalLease.mockImplementation(async () => { expect(returned).toBe(false); });
    const signed = await sign(asked, (await preview(asked, LEASED)).body);
    returned = true;
    expect(signed.status).toBe(200);
    expect(reservations()).toHaveLength(1);
    const [recorded] = reservations();
    expect(recorded).toMatchObject({ approvalRequestId: null, userId: owner.id, sessionId: `session_${owner.id}`, nodeOrigin: NODE });
    expect(recorded!.stage.leaseCid).toBe(signed.body.renewal.receipt.leaseCid);
    expect(recorded!.stage.leaseAuthorization).toBe(signed.body.renewal.receipt.leaseAuthorization);
  });

  test('a lease that cannot be recorded is not returned, and neither is the grant\'s signature', async () => {
    reserveRenewalLease.mockImplementation(async () => { throw new Error('database unavailable'); });
    const asked = await prepare();
    const signed = await sign(asked, (await preview(asked, LEASED)).body);
    expect(signed).toMatchObject({ status: 503, body: { code: 'renewal_failed' } });
    expect(signed.body).not.toHaveProperty('signature');
    expect(signed.body).not.toHaveProperty('renewal');
  });

  test('left unticked, the sign-in is finite: no lease and no node call', async () => {
    const asked = await prepare();
    const shown = await preview(asked, { choice: 'finite' });
    const signed = await sign(asked, shown.body);
    expect(signed.status).toBe(200);
    expect(signed.body.renewalChoice).toBe('finite');
    expect(signed.body).not.toHaveProperty('renewal');
    expect(signManagedMessage).toHaveBeenCalledTimes(1);
    expect(nodeCalls).toEqual([]);
    expect(reserveRenewalLease).not.toHaveBeenCalled();
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

  test('a node whose renewer cannot be confirmed gets no lease, and no signature is returned', async () => {
    identityAnswer = () => new Response('unavailable', { status: 503 });
    const asked = await prepare();
    const signed = await sign(asked, (await preview(asked, LEASED)).body);
    expect(signed).toMatchObject({ status: 503, body: { code: 'renewal_failed', error: "OpenKey couldn't set up renewal. Nothing was approved. Try again." } });
    expect(signed.body).not.toHaveProperty('signature');
    expect(signed.body).not.toHaveProperty('renewal');
    // Only the grant was signed.
    expect(signManagedMessage).toHaveBeenCalledTimes(1);
  });

  test('a lease the managed key fails to sign gets no lease, and no signature is returned', async () => {
    const asked = await prepare();
    const shown = await preview(asked, LEASED);
    let calls = 0;
    signManagedMessage.mockImplementation(async (message: string) => {
      if (++calls > 1) throw new Error('signer unavailable');
      return account.signMessage({ message });
    });
    try {
      const signed = await sign(asked, shown.body);
      expect(signed).toMatchObject({ status: 503, body: { code: 'renewal_failed' } });
      expect(signed.body).not.toHaveProperty('signature');
      expect(signed.body).not.toHaveProperty('renewal');
      expect(calls).toBe(2);
    } finally {
      signManagedMessage.mockImplementation(async (message: string) => account.signMessage({ message }));
    }
  });

  test('a shorter renewal chosen at the preview signs the shorter lease', async () => {
    const asked = await prepare();
    const shorter = { choice: 'leased', leaseLifetimeSeconds: 30 * DAY };
    const signed = await sign(asked, (await preview(asked, shorter)).body);
    expect(signed.status).toBe(200);
    const { renewal } = signed.body;
    expect(renewal.approvedLeaseLifetimeSeconds).toBe(30 * DAY);
    expect(Date.parse(renewal.receipt.leaseExpiresAt) - Date.parse(renewal.approvedAt)).toBe(30 * DAY * 1000);
  });

  test('a sign-in that never asked for renewal refuses one at signing, and signs nothing', async () => {
    const plain = await prepare({ expiryChangeable: true });
    const signed = await sign(plain, (await preview(plain)).body, { renewal: LEASED });
    expect(signed).toMatchObject({ status: 400, body: { code: 'request_binding' } });
    expect(signed.body).not.toHaveProperty('signature');
    expect(signManagedMessage).not.toHaveBeenCalled();
    expect(nodeCalls).toEqual([]);
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

  test('gets the lease to sign after the grant, and the signed lease back once the owner signs it', async () => {
    const grant = await signedGrant();
    expect(grant.renewalChoice).toBe('leased');
    expect(grant).not.toHaveProperty('renewal');
    const { message, leaseLifetimeSeconds, renewalToken } = grant.renewalSignature;
    expect(leaseLifetimeSeconds).toBe(90 * DAY);
    const cid = grantSetup(grant).delegationCid;
    expect(Object.keys(attenuation(message))).toEqual([`urn:cid:${cid}`]);

    const done = await post('/authorize-sign-renewal', { renewalToken, signature: await account.signMessage({ message }) });
    expect(done.status).toBe(200);
    expect(done.body).toMatchObject({ renewalChoice: 'leased', renewal: { version: 1, receipt: { originalCid: cid, leaseGeneration: 1 } } });
    expect(nodeCalls.sort()).toEqual(IDENTITY_READS);
    expect(await appAdmits(grant, done.body.renewal)).toEqual(done.body.renewal.receipt);
    // Taken once.
    expect((await post('/authorize-sign-renewal', { renewalToken, signature: await account.signMessage({ message }) })).status).toBe(410);
    // Recorded once, when the owner signed it: not while it waited for the wallet.
    expect(reservations()).toHaveLength(1);
    expect(reservations()[0]).toMatchObject({ approvalRequestId: null, userId: owner.id, sessionId: `session_${owner.id}`, nodeOrigin: NODE });
    expect(reservations()[0]!.stage.leaseCid).toBe(done.body.renewal.receipt.leaseCid);
  });

  test('another account gets no lease; another wallet\'s signature gets none either, and leaves it for the owner', async () => {
    const grant = await signedGrant();
    const { message, renewalToken } = grant.renewalSignature;
    currentUser = other;
    expect((await post('/authorize-sign-renewal', { renewalToken, signature: await account.signMessage({ message }) })).status).toBe(410);
    currentUser = owner;
    const wrong = await post('/authorize-sign-renewal', { renewalToken, signature: await stranger.signMessage({ message }) });
    expect(wrong).toMatchObject({ status: 400, body: { code: 'invalid_signature' } });
    expect(wrong.body).not.toHaveProperty('renewal');
    expect(reserveRenewalLease).not.toHaveBeenCalled();
    const done = await post('/authorize-sign-renewal', { renewalToken, signature: await account.signMessage({ message }) });
    expect(done).toMatchObject({ status: 200, body: { renewalChoice: 'leased' } });
  });

  test('a wallet-signed lease that cannot be recorded is not returned; the owner signs in again', async () => {
    const { renewalSignature: { message, renewalToken } } = await signedGrant();
    reserveRenewalLease.mockImplementation(async () => { throw new Error('database unavailable'); });
    const failed = await post('/authorize-sign-renewal', { renewalToken, signature: await account.signMessage({ message }) });
    expect(failed).toMatchObject({ status: 503, body: { code: 'renewal_failed' } });
    expect(failed.body).not.toHaveProperty('renewal');
  });

  test('the owner\'s signature on one sign-in\'s lease does not take another\'s', async () => {
    const first = await signedGrant();
    const second = await signedGrant();
    const firstSignature = await account.signMessage({ message: first.renewalSignature.message });
    const crossed = await post('/authorize-sign-renewal', { renewalToken: second.renewalSignature.renewalToken, signature: firstSignature });
    expect(crossed).toMatchObject({ status: 400, body: { code: 'invalid_signature' } });
    expect((await post('/authorize-sign-renewal', { renewalToken: first.renewalSignature.renewalToken, signature: firstSignature })).status).toBe(200);
  });

  test('requests racing to take the same lease: exactly one gets it', async () => {
    const { renewalSignature: { message, renewalToken } } = await signedGrant();
    const signature = await account.signMessage({ message });
    const answers = await Promise.all([1, 2, 3].map(() => post('/authorize-sign-renewal', { renewalToken, signature })));
    expect(answers.map((answer) => answer.status).sort()).toEqual([200, 410, 410]);
  });

  test('a lease not signed within ten minutes has lapsed', async () => {
    const { renewalSignature: { message, renewalToken } } = await signedGrant();
    const signature = await account.signMessage({ message });
    const now = Date.now();
    const clock = spyOn(Date, 'now').mockReturnValue(now + 10 * 60 * 1000 + 1);
    try {
      expect((await post('/authorize-sign-renewal', { renewalToken, signature })).status).toBe(410);
    } finally {
      clock.mockRestore();
    }
    expect((await post('/authorize-sign-renewal', { renewalToken, signature })).status).toBe(410);
  });
});
