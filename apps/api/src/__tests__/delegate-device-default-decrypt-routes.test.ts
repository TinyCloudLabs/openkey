// TC-1953: approving a device request that carries the default decrypt entry
// (service `tinycloud.encryption`, space `default`, empty path, decrypt only)
// through the /delegate approval routes. The approval baseline is built with
// the device transaction wherever the request names one, and only there.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import type { delegateRouter } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { mockModules, replaceModules } from './mock-module';

// Tests never touch a real home or tool home.
const testHome = mkdtempSync('/var/tmp/tc1953.');
process.env.HOME = testHome;
process.env.BUN_INSTALL_CACHE_DIR = testHome;
if (!process.env.HOME?.startsWith('/var/tmp/tc1953.')) throw new Error('test HOME is not a temp dir');

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const DECRYPT = 'tinycloud.encryption/decrypt';
const decryptEntry = { service: 'tinycloud.encryption', space: 'default', path: '', actions: [DECRYPT] };
const networkUrn = `urn:tinycloud:encryption:did:pkh:eip155:1:${account.address}:default`;
const SUBSET_ERROR = 'Edited permissions must be a subset of the original delegation request';

const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};

const activateSessionWithHost = mock(async () => ({ success: true }));
const deviceService = new DeviceAuthorizationService(new MemoryDeviceAuthorizationStore(), {
  verificationOrigin: 'https://openkey.so',
  encryptionSecret: 'test-device-authorization-secret-is-long-enough',
});

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
  '../routes/device-authorization': () => ({ deviceAuthorizationService: deviceService }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({
      deriveKey: mock(async () => new Uint8Array(32)),
      getQuote: mock(async () => 'quote'),
      isInTee: () => false,
    }),
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return { ...wallet, signMessage: async (input: { message: string }) => wallet.signMessage(input) };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;
let transactionId = '';

beforeAll(async () => {
  // Imported after mock.module (and with an isolating query) so the route
  // binds the mocked database, TEE, host activation, and device service.
  ({ delegateRouter: router } = await import('../routes/delegate?device-default-decrypt-routes-isolated' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?device-default-decrypt-routes-isolated' as string
  ));
});

beforeEach(async () => {
  resetContexts?.();
  activateSessionWithHost.mockClear();
  const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
  const started = await deviceService.start({
    deviceSecretHash: digest(`secret-${Math.random()}`),
    codeChallenge: digest(`verifier-${Math.random()}`),
    sessionDid: sessionDidForPublicJwk(jwk),
    publicJwk: jwk,
    relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
    permissions: [decryptEntry],
    nodeOrigin: host,
    shareOrigin: 'https://share.tinycloud.xyz',
    delegationTtlSeconds: 3600,
  }, `198.51.100.${Math.floor(Math.random() * 250)}`);
  transactionId = started.transactionId;
});

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** The /delegate page's /prepare body for this request. */
function pageBody(device: boolean) {
  return {
    keyId: keyRecord.id,
    jwk,
    host,
    prefix: 'default',
    permissions: [decryptEntry],
    expiry: '3600s',
    ...(device ? { deviceTransactionId: transactionId } : {}),
  };
}

async function prepare(device: boolean) {
  const prepared = await post('/prepare', pageBody(device));
  expect(prepared.status).toBe(200);
  return prepared;
}

/** The managed approval body: echoes the /prepare result. */
function managedApproval(prepared: { body: Record<string, any> }, device: boolean) {
  return {
    ...pageBody(device),
    prepared: prepared.body.prepared,
    authorizationContextToken: prepared.body.authorizationContext.token,
    selectedActionIds: prepared.body.selectedActionKeys,
    protocolVersion: 1,
  };
}

describe('device approval of the default decrypt entry (TC-1953)', () => {
  test('managed key: /prepare then POST / with the device transaction signs the default network entry', async () => {
    const prepared = await prepare(true);
    const signed = await post('/', managedApproval(prepared, true));
    expect(signed.body.error).toBeUndefined();
    expect(signed.status).toBe(200);
    expect(signed.body.delegationHeader).toBeDefined();
    expect(signed.body.permissions).toContainEqual({
      service: 'encryption',
      space: 'encryption',
      path: networkUrn,
      actions: [DECRYPT],
    });
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('wallet-signed /complete with the device transaction accepts the same entry', async () => {
    const prepared = await prepare(true);
    const signature = await account.signMessage({ message: prepared.body.prepared.siwe });
    const res = await post('/complete', {
      prepared: prepared.body.prepared,
      signature,
      host,
      jwk,
      permissions: [decryptEntry],
      deviceTransactionId: transactionId,
    });
    expect(res.body.error).toBeUndefined();
    expect(res.status).toBe(200);
  });

  test('a request without the device transaction is refused for the default network entry', async () => {
    // The network entry is bound at /prepare with the device transaction; an
    // approval that does not name one is checked against the ordinary baseline.
    const prepared = await prepare(true);
    const withoutDevice = await post('/', managedApproval(prepared, false));
    expect(withoutDevice.status).toBe(400);
    expect(withoutDevice.body.error).toContain(SUBSET_ERROR);
    expect(withoutDevice.body.delegationHeader).toBeUndefined();
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('/complete without the device transaction is refused for the default network entry', async () => {
    const prepared = await prepare(true);
    const signature = await account.signMessage({ message: prepared.body.prepared.siwe });
    const res = await post('/complete', {
      prepared: prepared.body.prepared,
      signature,
      host,
      jwk,
      permissions: [decryptEntry],
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain(SUBSET_ERROR);
  });

  test('a plain /prepare of the entry signs no network resource', async () => {
    const prepared = await prepare(false);
    expect(prepared.body.prepared.siwe).not.toContain('urn:tinycloud:encryption:');
  });

  test('legacy token-less POST / with the device transaction signs the default network entry', async () => {
    const res = await post('/', pageBody(true));
    expect(res.body.error).toBeUndefined();
    expect(res.status).toBe(200);
    expect(res.body.permissions).toContainEqual({
      service: 'encryption',
      space: 'encryption',
      path: networkUrn,
      actions: [DECRYPT],
    });
  });

  test('legacy token-less POST / without the device transaction signs no network resource', async () => {
    const res = await post('/', pageBody(false));
    expect(res.body.permissions ?? []).not.toContainEqual(expect.objectContaining({ path: networkUrn }));
  });
});
