import { afterAll, beforeAll, beforeEach, expect, mock, spyOn, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { verifyMessage } from 'ethers';
import * as capabilityReview from '@openkey/capability-review';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { DeviceAuthorizationService, MemoryDeviceAuthorizationStore, sessionDidForPublicJwk, type DeviceRelayEnvelope } from '../services/device-authorization';
import { decodeScope, encodeScope } from '../services/device-authorization-store';
import type { delegateRouter } from '../routes/delegate';
import { parsePreparedRecap } from '../routes/delegate-session';
import type { RenewalStage } from '../services/renewal-lease';
import { mockModules, replaceModules } from './mock-module';

const host = 'http://127.0.0.1:8744';
const nodeDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const renewerDid = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'device-renewal-owner', email: 'owner@example.test' };
const managed = { id: 'key', userId: user.id, address: account.address, keyType: 'MANAGED', sealedBlob: 'test-blob', sealingContext: null };
const wallet = { ...managed, keyType: 'EXTERNAL', sealedBlob: null };
let key: typeof managed | typeof wallet = managed;
const prisma = {
  ethereumKey: { findFirst: async () => key },
  user: { findUnique: async () => ({ autoSignEnabled: true }) },
  appSignInDay: { upsert: async () => {}, deleteMany: async () => {} },
};
const signOwner = mock(async (message: string) => account.signMessage({ message }));
const activateSessionWithHost = mock(async () => ({ success: true }));
const reserve = mock(async (_db: unknown, _input: {
  userId: string; sessionId: string | null; approvalRequestId: string | null; nodeOrigin: string; stage: RenewalStage;
}) => {});
const relayPublicJwk = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const credentials = { deviceSecret: 'test-device-secret', codeVerifier: 'test-code-verifier' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) };
const space = `tinycloud:pkh:eip155:1:${account.address}:default`;
const permissions = [
  { service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
  { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] },
];
const ask = { version: 1, leaseLifetimeSeconds: 30 * 86_400 } as const;
const leased = { choice: 'leased', leaseLifetimeSeconds: ask.leaseLifetimeSeconds };
const finite = { choice: 'finite' };
const store = new MemoryDeviceAuthorizationStore();
let timeOffset = 0;
const device = new DeviceAuthorizationService(store, {
  verificationOrigin: 'https://openkey.test',
  encryptionSecret: 'test-device-authorization-secret-is-long-enough',
  now: () => new Date(Date.now() + timeOffset),
});

const signedIn = createMiddleware(async (c, next) => {
  c.set('user', user);
  c.set('session', { id: 'phone-session', userId: user.id });
  c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
  await next();
});
replaceModules({
  '../middleware/session': () => ({ requireSession: signedIn }),
  '../routes/device-authorization': () => ({ deviceAuthorizationService: device }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: async () => new Uint8Array(32), isInTee: () => false }),
    unseal: async () => privateKey,
    createWalletFromPrivateKey: () => ({ signMessage: ({ message }: { message: string }) => signOwner(message) }),
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
  '../services/renewal-lease-revocation': () => ({ reserveRenewalLease: reserve }),
  '../services/tinycloud-bootstrap': () => ({ ensureTinyCloudBootstrap: async () => ({ status: 'complete' }) }),
});

let router: typeof delegateRouter;
const realFetch = globalThis.fetch;
const savedFlag = process.env.OPENKEY_RENEWAL_LEASES;
beforeAll(async () => {
  const routes = await import('../routes/delegate?device-renewal-test' as string);
  router = routes.delegateRouter;
  routes.setDelegateSignerAuthMiddlewareForTests(signedIn);
});
beforeEach(() => {
  key = managed;
  timeOffset = 0;
  process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
  signOwner.mockClear();
  reserve.mockClear();
  reserve.mockImplementation(async () => {});
  activateSessionWithHost.mockClear();
  globalThis.fetch = (async (request: RequestInfo | URL) => {
    const url = new URL(String(request));
    if (url.origin === host && url.pathname === '/info') return Response.json({ nodeId: nodeDid });
    if (url.origin === host && url.pathname === '/.well-known/tinycloud/node-keys') {
      return Response.json({ nodeDid, renewerDid, renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik', renewerEpoch: 0 });
    }
    throw new Error(`Unexpected node request ${url}`);
  }) as typeof fetch;
});
afterAll(() => {
  globalThis.fetch = realFetch;
  if (savedFlag === undefined) delete process.env.OPENKEY_RENEWAL_LEASES;
  else process.env.OPENKEY_RENEWAL_LEASES = savedFlag;
});

function start(overrides: Partial<Parameters<typeof device.start>[0]> = {}) {
  return device.start({
    deviceSecretHash: digest(credentials.deviceSecret),
    codeChallenge: digest(credentials.codeVerifier),
    sessionDid: sessionDidForPublicJwk(jwk),
    publicJwk: jwk,
    relayPublicJwk: relayPublicJwk(),
    permissions,
    nodeOrigin: host,
    shareOrigin: 'https://share.example.test',
    delegationTtlSeconds: 7 * 86_400,
    renewal: { version: 1, leaseLifetimeSeconds: ask.leaseLifetimeSeconds },
    ...overrides,
  }, randomBytes(16).toString('hex'));
}

async function post(path: string, body: Record<string, unknown>) {
  const response = await router.request(path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() as Record<string, any> };
}

function prepare(transactionId: string, renewal: unknown, actionKeys?: string[]) {
  return post('/prepare', { keyId: key.id, jwk, host, permissions, expiry: '1h', deviceTransactionId: transactionId, renewal, actionKeys });
}

function approvalBody(transactionId: string, preview: Record<string, any>) {
  return {
    keyId: key.id, jwk, host, permissions, expiry: '1h', deviceTransactionId: transactionId,
    prepared: preview.prepared, authorizationContextToken: preview.authorizationContext.token,
    selectedActionIds: preview.selectedActionKeys, protocolVersion: 1,
  };
}

test('binds eligible start asks and retains the existing finite protocol for other rows', async () => {
  for (const leaseLifetimeSeconds of [0, -1, 1.5, 365 * 86_400 + 1]) {
    await expect(start({ renewal: { version: 1, leaseLifetimeSeconds } })).rejects.toMatchObject({ code: 'invalid_renewal_request' });
  }
  const started = await start();
  expect((await device.lookup(started.userCode))?.renewal).toEqual(ask);
  const record = (await store.findById(started.transactionId))!;
  const dates = { delegationExpiresAt: record.delegationExpiresAt, transactionExpiresAt: record.transactionExpiresAt };
  expect(decodeScope({ ...dates, permissions: encodeScope(record) }).renewal).toEqual(ask);
  expect(decodeScope({ ...dates, permissions }).renewal).toBeUndefined();
  const otherNode = await start({ nodeOrigin: 'https://other.example.test' });
  expect((await device.lookup(otherNode.userCode))?.renewal).toBeUndefined();
  const share = await start({ permissions: [{ ...permissions[1]!, space: 'applications' }] });
  expect(await device.lookup(share.userCode)).toMatchObject({ shareOnly: true });
  expect((await device.lookup(share.userCode))?.renewal).toBeUndefined();
  delete process.env.OPENKEY_RENEWAL_LEASES;
  expect((await device.lookup(started.userCode))?.renewal).toBeUndefined();
});

test('signs and records a lease for the exact device grant, then polls the opaque result until ACK', async () => {
  const { transactionId } = await start();
  const full = await prepare(transactionId, leased);
  expect(full.status).toBe(200);
  const actionKeys = (full.body.selectedActionKeys as string[]).filter((action) => !action.endsWith('tinycloud.kv/put'));
  expect(actionKeys.length).toBeLessThan(full.body.selectedActionKeys.length);
  const preview = await prepare(transactionId, leased, actionKeys);
  expect(preview.status).toBe(200);
  const result = await post('/', approvalBody(transactionId, preview.body));
  expect(result).toMatchObject({ status: 200, body: { hostActivated: true } });
  const grantedActions = parsePreparedRecap(result.body.signedMessage).flatMap((grant) => grant.actions);
  expect(grantedActions).toContain('tinycloud.kv/get');
  expect(grantedActions).not.toContain('tinycloud.kv/put');
  const receipt = result.body.renewal.receipt;
  const reservation = reserve.mock.calls[0]?.[1];
  expect(reservation).toMatchObject({
    userId: user.id, sessionId: null, approvalRequestId: null, nodeOrigin: host,
    stage: { originalCid: result.body.delegationCid, leaseCid: receipt.leaseCid, leaseAuthorization: receipt.leaseAuthorization },
  });
  expect(receipt).toMatchObject({ originalCid: result.body.delegationCid, nodeIdentity: { nodeDid, renewerDid }, leaseGeneration: 1 });
  expect(signOwner).toHaveBeenCalledTimes(2);
  expect(signOwner.mock.calls[0]?.[0]).toBe(preview.body.prepared.siwe);
  const leaseSignature = await signOwner.mock.results[1]?.value;
  if (typeof leaseSignature !== 'string') throw new Error('Expected a lease signature');
  expect(verifyMessage(reservation!.stage.leaseSiwe, leaseSignature)).toBe(account.address);
  expect(reservation!.stage.leaseSiwe).toContain(renewerDid);
  expect(activateSessionWithHost).toHaveBeenCalledTimes(1);

  const relay: DeviceRelayEnvelope = {
    version: 1, algorithm: 'ECDH-P256-A256GCM',
    ephemeralPublicJwk: relayPublicJwk() as DeviceRelayEnvelope['ephemeralPublicJwk'],
    nonce: randomBytes(12).toString('base64url'), ciphertext: randomBytes(48).toString('base64url'),
  };
  const auth = { transactionId, ...credentials };
  await device.approve(transactionId, user.id, { relay, binding: {
    transactionId, sessionDid: sessionDidForPublicJwk(jwk), nodeOrigin: host, shareOrigin: 'https://share.example.test',
    permissions: [{ ...permissions[0]!, actions: ['tinycloud.kv/get'] }, permissions[1]],
    delegationExpiresAt: result.body.expirationTime,
  } });
  const first = await device.poll(auth);
  timeOffset += 2_100;
  const second = await device.poll(auth);
  if (first.status !== 'approved' || second.status !== 'approved') throw new Error('Expected approved results');
  expect(first.relay).toEqual(relay);
  expect(second.relay).toEqual(relay);
  expect(first.serverTime).toBeString();
  expect(second.serverTime).toBeString();
  expect(Date.parse(second.serverTime!)).toBeGreaterThan(Date.parse(first.serverTime!));
  expect(JSON.stringify(second)).not.toContain(receipt.leaseAuthorization);
  expect(await device.acknowledge(auth)).toEqual({ status: 'acknowledged' });
  expect(await device.acknowledge(auth)).toEqual({ status: 'acknowledged' });
  expect((await store.findById(transactionId))?.encryptedResult).toBeUndefined();
});

test('refuses a changed, missing or swapped preview binding before managed signing', async () => {
  const { transactionId } = await start();
  const other = await start();
  expect(await prepare(transactionId, undefined)).toMatchObject({ status: 400, body: { code: 'request_binding' } });
  expect(await prepare(transactionId, { ...leased, leaseLifetimeSeconds: ask.leaseLifetimeSeconds + 1 }))
    .toMatchObject({ status: 400, body: { code: 'request_binding' } });
  expect(await prepare((await start({ renewal: undefined })).transactionId, leased))
    .toMatchObject({ status: 400, body: { code: 'request_binding' } });
  const preview = await prepare(transactionId, leased);
  expect(preview.status).toBe(200);
  const body = approvalBody(transactionId, preview.body);
  for (const candidate of [
    { ...body, deviceTransactionId: undefined },
    { ...body, deviceTransactionId: other.transactionId },
    { ...body, renewal: finite },
    { ...body, protocolVersion: undefined, authorizationContextToken: undefined },
  ]) {
    expect(await post('/', candidate)).toMatchObject({ status: 400, body: { code: 'request_binding' } });
  }
  expect(signOwner).not.toHaveBeenCalled();
});

test('keeps a failed setup pending and permits a newly prepared finite approval', async () => {
  const { transactionId } = await start();
  const preview = await prepare(transactionId, leased);
  expect(preview.status).toBe(200);
  reserve.mockImplementation(async () => { throw new Error('reservation unavailable'); });
  expect(await post('/', approvalBody(transactionId, preview.body))).toMatchObject({
    status: 503,
    body: { code: 'renewal_failed', error: "OpenKey couldn't set up renewal. This device is waiting for your approval. You can approve it without renewal." },
  });
  expect((await store.findById(transactionId))?.status).toBe('pending');
  expect(activateSessionWithHost).not.toHaveBeenCalled();
  const optOut = await prepare(transactionId, finite);
  expect(optOut.status).toBe(200);
  expect(await post('/', approvalBody(transactionId, optOut.body))).toMatchObject({
    status: 200, body: { renewal: null, renewalReason: 'renewal_declined' },
  });
});

test('requires finite consent for wallets and after the feature is disabled', async () => {
  const { transactionId } = await start();
  key = wallet;
  expect(await prepare(transactionId, leased)).toMatchObject({
    status: 400,
    body: { code: 'request_binding', error: "Your wallet signs in for a set time, so this device's access ends at the time shown." },
  });
  const prepared = await prepare(transactionId, finite);
  expect(prepared.status).toBe(200);
  const signature = await account.signMessage({ message: prepared.body.prepared.siwe });
  expect(await post('/complete', { ...approvalBody(transactionId, prepared.body), signature })).toMatchObject({
    status: 200, body: { renewal: null, renewalReason: 'renewal_wallet_unsupported' },
  });
  key = managed;
  const preview = await prepare(transactionId, leased);
  expect(preview.status).toBe(200);
  delete process.env.OPENKEY_RENEWAL_LEASES;
  expect(await post('/', approvalBody(transactionId, preview.body))).toMatchObject({
    status: 400,
    body: { code: 'renewal_disabled', error: "Renewal isn't available for this sign-in. You can approve it without renewal." },
  });
  expect(signOwner).not.toHaveBeenCalled();
  expect(reserve).not.toHaveBeenCalled();
});


test.each([
  { name: 'refuses a sensitive device grant without confirmation', expiry: '7d', confirmed: false, status: 400 },
  { name: 'refuses a confirmed sensitive device grant with an eight-day window', expiry: '8d', confirmed: true, status: 400 },
  { name: 'signs a confirmed sensitive device grant with a seven-day window', expiry: '7d', confirmed: true, status: 200 },
])('$name', async ({ expiry, confirmed, status }) => {
  // The current device allowlist excludes sensitive grants. Inject one sensitivity verdict while exercising D7
  // against the actual prepared SIWE, with the real device scope checks, window calculation and managed signing.
  const classify = capabilityReview.renewalEntryVerdict;
  const sensitivity = spyOn(capabilityReview, 'renewalEntryVerdict').mockImplementation((entry) =>
    entry.actions.includes('tinycloud.kv/get') ? 'confirm' : classify(entry));
  try {
    const { transactionId } = await start({ delegationTtlSeconds: 8 * 86_400 });
    const preview = await post('/prepare', {
      keyId: key.id, jwk, host, permissions, expiry, deviceTransactionId: transactionId,
      renewal: { ...leased, ...(confirmed ? { sensitiveConfirmed: true } : {}) },
    });
    expect(preview.status).toBe(status);
    if (status === 400) {
      expect(preview.body.code).toBe('renewal_refused');
      expect(preview.body).not.toHaveProperty('authorizationContext');
      expect(signOwner).not.toHaveBeenCalled();
      expect(reserve).not.toHaveBeenCalled();
      return;
    }

    const result = await post('/', { ...approvalBody(transactionId, preview.body), expiry });
    expect(result.status).toBe(200);
    expect(result.body.renewal.receipt.originalCid).toBe(result.body.delegationCid);
    expect(reserve).toHaveBeenCalledTimes(1);
  } finally {
    sensitivity.mockRestore();
  }
});
