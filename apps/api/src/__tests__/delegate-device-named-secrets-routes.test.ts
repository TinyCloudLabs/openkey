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
const capabilities = { service: 'tinycloud.capabilities', space: 'secrets', path: '', actions: ['tinycloud.capabilities/read'] };
const named = { service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/FIRST_KEY', actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/list'] };
const names = { ...named, path: 'vault/secrets/', actions: ['tinycloud.kv/list'] };
const decrypt = { service: 'tinycloud.encryption', space: 'default', path: '', actions: ['tinycloud.encryption/decrypt'] };
const secretsSpaceId = `tinycloud:pkh:eip155:1:${account.address}:secrets`;
const permissions = [capabilities, named, decrypt];

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
  const { request } = await startRequest([capabilities, writeOnly]);
  const prepared = await post('/prepare', request);
  expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
  const signed = await post('/', { ...request, ...managedApproval(prepared.body) });
  expect(signed.status, JSON.stringify(signed.body)).toBe(200);
  expect(prepared.body.spaceId).toBe(secretsSpaceId);
  expect(signed.body.spaceId).toBe(secretsSpaceId);
  expect(signed.body.permissions).toEqual(expect.arrayContaining([
    { ...capabilities, service: 'capabilities', space: secretsSpaceId },
    { ...writeOnly, service: 'kv', space: secretsSpaceId },
  ]));
  expect(signed.body.permissions).toHaveLength(2);
});

test('prepares and signs a names-only request in the secrets space', async () => {
  const { request } = await startRequest([capabilities, names]);
  const prepared = await post('/prepare', request);
  expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
  const signed = await post('/', { ...request, ...managedApproval(prepared.body) });
  expect(signed.status, JSON.stringify(signed.body)).toBe(200);
  expect(signed.body.spaceId).toBe(secretsSpaceId);
  expect(signed.body.permissions).toEqual(expect.arrayContaining([
    { ...capabilities, service: 'capabilities', space: secretsSpaceId },
    { ...names, service: 'kv', space: secretsSpaceId },
  ]));
  expect(signed.body.permissions).toHaveLength(2);
});

test.each(['secrets', secretsSpaceId])('prepares, signs and relays a CLI request for %s', async (space) => {
  const second = { ...named, space, path: 'vault/secrets/SECOND_KEY', actions: ['tinycloud.kv/put'] };
  const requested = [{ ...capabilities, space }, { ...named, space }, second, { ...names, space }, decrypt];
  const { request, poll } = await startRequest(requested);
  const prepared = await post('/prepare', request);
  expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
  const signed = await post('/', { ...request, ...managedApproval(prepared.body) });
  expect(signed.status, JSON.stringify(signed.body)).toBe(200);
  expect(prepared.body.spaceId).toBe(secretsSpaceId);
  expect(signed.body.spaceId).toBe(secretsSpaceId);
  expect(signed.body.permissions).toEqual(expect.arrayContaining([
    { ...capabilities, service: 'capabilities', space: secretsSpaceId },
    { ...second, service: 'kv', space: secretsSpaceId },
    { ...names, service: 'kv', space: secretsSpaceId },
    { service: 'encryption', space: 'encryption', path: `urn:tinycloud:encryption:did:pkh:eip155:1:${account.address}:default`, actions: decrypt.actions },
  ]));
  const signedNamed = signed.body.permissions.find((entry: { path: string }) => entry.path === named.path);
  expect(signedNamed).toEqual({ ...named, service: 'kv', space: secretsSpaceId, actions: expect.arrayContaining(named.actions) });
  expect(signedNamed.actions).toHaveLength(named.actions.length);
  expect(signed.body.permissions).toHaveLength(5);

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
      permissions: requested,
      delegationExpiresAt: signed.body.expiresAt,
    },
  });
  expect(await deviceService.poll(poll)).toMatchObject({
    status: 'approved', binding: { permissions: requested, delegationExpiresAt: signed.body.expiresAt },
  });
});

test('refuses out-of-policy named and prefix abilities even if they are unchecked', async () => {
  signMessage.mockClear();
  activateSessionWithHost.mockClear();
  const { request } = await startRequest();
  const prepared = await post('/prepare', request);
  expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
  const approval = managedApproval(prepared.body);
  const signature = await account.signMessage({ message: approval.prepared.siwe });

  for (const permissions of [
    [capabilities, { ...named, actions: [...named.actions, 'tinycloud.kv/del'] }, decrypt],
    [capabilities, named, { ...names, actions: ['tinycloud.kv/get'] }, decrypt],
  ]) {
    const altered = { ...request, permissions, actionKeys: prepared.body.selectedActionKeys };
    for (const refused of [
      await post('/prepare', altered),
      await post('/', altered),
      await post('/', { ...altered, ...approval }),
      await post('/complete', { ...altered, ...approval, signature }),
    ]) {
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe('invalid_permissions');
    }
  }
  expect(signMessage).not.toHaveBeenCalled();
  expect(activateSessionWithHost).not.toHaveBeenCalled();
});
