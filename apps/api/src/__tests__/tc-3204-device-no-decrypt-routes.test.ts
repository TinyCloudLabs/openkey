// TC-3204: a device request can't carry decrypt, so its record never holds an encryption entry. An approval body that
// adds one (the whole network, the `share/` prefix, one shared file, or another spelling of the encryption service) is
// refused on every /api/delegate path, and nothing is signed or activated.

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
const testHome = mkdtempSync('/var/tmp/tc3204.');
process.env.HOME = testHome;
process.env.BUN_INSTALL_CACHE_DIR = testHome;
if (!process.env.HOME?.startsWith('/var/tmp/tc3204.')) throw new Error('test HOME is not a temp dir');

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
const leaf = { service: 'tinycloud.encryption', space: 'default', path: 'share/3f9c1a7e5b2d48a09c6e1f7a2b4d8c03', actions: [DECRYPT] };
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${account.address}:default`;
const requested = [
  { service: 'tinycloud.kv', space: 'default', path: 'notes/', actions: ['tinycloud.kv/get'] },
  { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] },
];

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
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrap: mock(async () => ({ status: 'complete' as const })),
  }),
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
  ({ delegateRouter: router } = await import('../routes/delegate?tc-3204-device-no-decrypt-routes' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?tc-3204-device-no-decrypt-routes' as string
  ));
});

beforeEach(async () => {
  resetContexts?.();
  activateSessionWithHost.mockClear();
  const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
  ({ transactionId } = await deviceService.start({
    deviceSecretHash: digest(`secret-${Math.random()}`),
    codeChallenge: digest(`verifier-${Math.random()}`),
    sessionDid: sessionDidForPublicJwk(jwk),
    publicJwk: jwk,
    relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
    permissions: requested,
    nodeOrigin: host,
    shareOrigin: 'https://share.tinycloud.xyz',
    delegationTtlSeconds: 3600,
  }, `198.51.100.${Math.floor(Math.random() * 250)}`));
});

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

const added: Array<[string, Record<string, unknown>]> = [
  ['the network URN', { service: 'tinycloud.encryption', space: 'encryption', path: network, actions: [DECRYPT] }],
  ['the share/ prefix on the network', { service: 'tinycloud.encryption', space: 'encryption', path: `${network}/share/`, actions: [DECRYPT] }],
  ['the share/ prefix', { ...leaf, path: 'share/' }],
  ['the whole default network', { ...leaf, path: '' }],
  ['one shared file', leaf],
  ['one shared file under an upper-case service', { ...leaf, service: 'TINYCLOUD.ENCRYPTION' }],
];

describe('a device request approved with an added decrypt (TC-3204)', () => {
  for (const [name, entry] of added) {
    test(`${name} is refused at /prepare, legacy POST / and /complete, and nothing is signed or activated`, async () => {
      const permissions = [...requested, entry];
      const page = { keyId: keyRecord.id, jwk, host, prefix: 'default', permissions, expiry: '3600s', deviceTransactionId: transactionId };
      const prepared = await post('/prepare', page);
      expect(prepared.status).toBe(400);
      expect(prepared.body.prepared).toBeUndefined();

      const legacy = await post('/', page);
      expect(legacy.status).toBe(400);
      expect(legacy.body.delegationHeader).toBeUndefined();

      // A wallet that signed the wider bytes (prepared without the device id) is refused at /complete.
      const unnamed = await post('/prepare', { ...page, deviceTransactionId: undefined });
      if (unnamed.status === 200) {
        const signature = await account.signMessage({ message: unnamed.body.prepared.siwe });
        const completed = await post('/complete', { prepared: unnamed.body.prepared, signature, host, jwk, permissions, deviceTransactionId: transactionId });
        expect(completed.status).toBe(400);
        expect(completed.body.delegationHeader).toBeUndefined();
      }
      expect(activateSessionWithHost).not.toHaveBeenCalled();
    });
  }

  test('the recorded request itself is signed', async () => {
    const signed = await post('/', { keyId: keyRecord.id, jwk, host, prefix: 'default', permissions: requested, expiry: '3600s', deviceTransactionId: transactionId });
    expect(signed.status).toBe(200);
    expect(signed.body.delegationHeader).toBeDefined();
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });
});
