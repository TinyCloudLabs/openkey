import { beforeAll, expect, mock, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter } from '../routes/delegate';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'fixture-user', email: 'owner@example.test' };
const key = { id: 'fixture-key', address: account.address, userId: user.id, keyType: 'MANAGED', sealedBlob: 'sealed-blob' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) };
const host = 'https://node.example.test';
const shareOrigin = 'https://share.example.test';
const signMessage = mock((input: { message: string }) => account.signMessage(input));
const activateSessionWithHost = mock(async () => ({ success: true }));
const deviceService = new DeviceAuthorizationService(new MemoryDeviceAuthorizationStore(), {
  verificationOrigin: 'https://openkey.example.test',
  encryptionSecret: 'fixture-device-authorization-encryption-key',
});
const named = { service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/FIRST_KEY', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] };
const decrypt = { service: 'tinycloud.encryption', space: 'default', path: '', actions: ['tinycloud.encryption/decrypt'] };
const permissions = [named, decrypt];

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'fixture-session', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
  '../routes/device-authorization': () => ({ deviceAuthorizationService: deviceService }),
});
await mockModules({
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrap: mock(async () => ({ status: 'complete' as const })),
  }),
  '@openkey/db': () => ({
    createPrismaClient: () => ({
      ethereumKey: { findFirst: async () => key, findMany: async () => [key] },
      user: { findUnique: async () => ({ autoSignEnabled: true }) },
      tinyCloudBootstrapState: {},
    }),
  }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({
      deriveKey: async () => new Uint8Array(32),
      getQuote: async () => 'quote',
      isInTee: () => false,
    }),
    unseal: async () => privateKey,
    createWalletFromPrivateKey: () => ({ ...account, signMessage }),
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
});

let router: typeof delegateRouter;
beforeAll(async () => {
  ({ delegateRouter: router } = await import('../routes/delegate?device-named-secrets-routes' as string));
});

async function startRequest(requested = permissions) {
  const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
  const deviceSecret = randomBytes(32).toString('base64url');
  const codeVerifier = randomBytes(32).toString('base64url');
  const relayKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
  const { transactionId } = await deviceService.start({
    deviceSecretHash: digest(deviceSecret),
    codeChallenge: digest(codeVerifier),
    sessionDid: sessionDidForPublicJwk(jwk),
    publicJwk: jwk,
    relayPublicJwk: relayKey,
    permissions: requested,
    nodeOrigin: host,
    shareOrigin,
    delegationTtlSeconds: 3600,
  }, '198.51.100.20');
  return {
    request: { keyId: key.id, jwk, host, expiry: '3600s', permissions: requested, deviceTransactionId: transactionId },
    poll: { transactionId, deviceSecret, codeVerifier },
  };
}

async function post(path: string, body: Record<string, unknown>) {
  const response = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as Record<string, any> };
}

function managedApproval(body: Record<string, any>) {
  return {
    prepared: body.prepared,
    authorizationContextToken: body.authorizationContext.token,
    selectedActionIds: body.selectedActionKeys,
    protocolVersion: 1,
  };
}

test('prepares and signs a write-only secret from a manifest', async () => {
  const writeOnly = { ...named, actions: ['tinycloud.kv/put'] };
  const { request } = await startRequest([writeOnly]);
  const prepared = await post('/prepare', request);
  expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
  const signed = await post('/', { ...request, ...managedApproval(prepared.body) });
  expect(signed.status, JSON.stringify(signed.body)).toBe(200);
  expect(signed.body.permissions).toEqual([
    { ...writeOnly, service: 'kv', space: `tinycloud:pkh:eip155:1:${account.address}:secrets` },
  ]);
});

test('prepares, signs and relays the named KV path and the signer’s default network', async () => {
  const { request, poll } = await startRequest();
  const prepared = await post('/prepare', request);
  expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
  const signed = await post('/', { ...request, ...managedApproval(prepared.body) });
  expect(signed.status, JSON.stringify(signed.body)).toBe(200);
  expect(signed.body.permissions).toEqual(expect.arrayContaining([
    { ...named, service: 'kv', space: `tinycloud:pkh:eip155:1:${account.address}:secrets` },
    { service: 'encryption', space: 'encryption', path: `urn:tinycloud:encryption:did:pkh:eip155:1:${account.address}:default`, actions: decrypt.actions },
  ]));
  expect(signed.body.permissions).toHaveLength(2);

  const ephemeralPublicJwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
  await deviceService.approve(poll.transactionId, user.id, {
    relay: {
      version: 1,
      algorithm: 'ECDH-P256-A256GCM',
      ephemeralPublicJwk,
      nonce: randomBytes(12).toString('base64url'),
      ciphertext: randomBytes(64).toString('base64url'),
    },
    binding: {
      transactionId: poll.transactionId,
      sessionDid: sessionDidForPublicJwk(jwk),
      nodeOrigin: host,
      shareOrigin,
      permissions,
      delegationExpiresAt: signed.body.expiresAt,
    },
  });
  expect(await deviceService.poll(poll)).toMatchObject({
    status: 'approved', binding: { permissions, delegationExpiresAt: signed.body.expiresAt },
  });
});

test('refuses a device baseline with an out-of-policy ability even if it is unchecked', async () => {
  signMessage.mockClear();
  activateSessionWithHost.mockClear();
  const { request } = await startRequest();
  const prepared = await post('/prepare', request);
  expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
  const altered = {
    ...request,
    permissions: [{ ...named, actions: [...named.actions, 'tinycloud.kv/del'] }, decrypt],
    actionKeys: prepared.body.selectedActionKeys,
  };
  const approval = managedApproval(prepared.body);
  const signature = await account.signMessage({ message: approval.prepared.siwe });

  for (const refused of [
    await post('/prepare', altered),
    await post('/', altered),
    await post('/', { ...altered, ...approval }),
    await post('/complete', { ...altered, ...approval, signature }),
  ]) {
    expect(refused.status).toBe(400);
    expect(refused.body.code).toBe('invalid_permissions');
  }
  expect(signMessage).not.toHaveBeenCalled();
  expect(activateSessionWithHost).not.toHaveBeenCalled();
});
