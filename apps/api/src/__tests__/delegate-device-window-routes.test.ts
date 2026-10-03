// TC-539: /api/delegate routes refuse a device-transaction delegation whose
// lifetime, Node origin, or session key fall outside the pending device
// request, before signing and before any host activation.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import type { delegateRouter } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';

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

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
mock.module('@openkey/tee', () => ({
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
}));
mock.module('@tinycloud/sdk-core', () => ({ activateSessionWithHost }));
mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
    await next();
  }),
}));
mock.module('../routes/device-authorization', () => ({ deviceAuthorizationService: deviceService }));

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;
let transactionId = '';

beforeAll(async () => {
  // Imported after mock.module (and with an isolating query) so the route
  // binds the mocked database, TEE, host activation, and device service.
  ({ delegateRouter: router } = await import('../routes/delegate?device-window-routes-isolated' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?device-window-routes-isolated' as string
  ));
});

beforeEach(async () => {
  resetContexts?.();
  activateSessionWithHost.mockClear();
  // A fresh 60-second device transaction for the test session key and host.
  const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
  const started = await deviceService.start({
    deviceSecretHash: digest(`secret-${Math.random()}`),
    codeChallenge: digest(`verifier-${Math.random()}`),
    sessionDid: sessionDidForPublicJwk(jwk),
    publicJwk: jwk,
    relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
    permissions: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }],
    nodeOrigin: host,
    shareOrigin: 'https://share.tinycloud.xyz',
    delegationTtlSeconds: 60,
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

async function prepare(expiry: string, device: boolean) {
  return post('/prepare', { keyId: keyRecord.id, jwk, host, expiry, ...(device ? { deviceTransactionId: transactionId } : {}) });
}

describe('device delegation window on /api/delegate', () => {
  test('/prepare refuses an expiry beyond the transaction lifetime and accepts one within it', async () => {
    const overlong = await prepare('90d', true);
    expect(overlong.status).toBe(400);
    expect(overlong.body.code).toBe('invalid_request');
    expect((await prepare('60s', true)).status).toBe(200);
  });

  test('managed signing refuses an overlong device delegation before signing or host activation', async () => {
    // Bypass /prepare's check: prepare without the device id, sign with it.
    const prepared = await prepare('90d', false);
    expect(prepared.status).toBe(200);
    const versioned = await post('/', {
      keyId: keyRecord.id,
      jwk,
      host,
      prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
      deviceTransactionId: transactionId,
    });
    expect(versioned.status).toBe(400);
    expect(versioned.body.delegationHeader).toBeUndefined();

    const legacy = await post('/', { keyId: keyRecord.id, jwk, host, expiry: '90d', deviceTransactionId: transactionId });
    expect(legacy.status).toBe(400);
    expect(legacy.body.delegationHeader).toBeUndefined();
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('managed signing refuses another host for the device transaction', async () => {
    const res = await post('/', { keyId: keyRecord.id, jwk, host: 'https://attacker.example', expiry: '60s', deviceTransactionId: transactionId });
    expect(res.status).toBe(400);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('wallet-signed /complete refuses an overlong device delegation before host activation', async () => {
    const prepared = await prepare('90d', false);
    const signature = await account.signMessage({ message: prepared.body.prepared.siwe });
    const res = await post('/complete', { prepared: prepared.body.prepared, signature, host, jwk, deviceTransactionId: transactionId });
    expect(res.status).toBe(400);
    expect(res.body.delegationHeader).toBeUndefined();
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('a delegation within the lifetime is signed and activated', async () => {
    const prepared = await prepare('60s', true);
    const res = await post('/', {
      keyId: keyRecord.id,
      jwk,
      host,
      prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
      deviceTransactionId: transactionId,
    });
    expect(res.status).toBe(200);
    expect(res.body.delegationHeader).toBeDefined();
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('refuses reshaped spellings of the session JWK for a named transaction', async () => {
    const reshapedKeys = [
      { ...jwk, d: null }, { ...jwk, p: 'x' }, { ...jwk, use: 'sig' }, { ...jwk, x: `${jwk.x}=` },
      { ...jwk, kid: null }, { ...jwk, kid: 7 }, { ...jwk, kid: '' },
    ];
    for (const reshaped of reshapedKeys) {
      const prepared = await post('/prepare', { keyId: keyRecord.id, jwk: reshaped, host, expiry: '60s', deviceTransactionId: transactionId });
      expect(prepared.status).toBe(400);
      expect(prepared.body.code).toBe('invalid_request');
      const signed = await post('/', { keyId: keyRecord.id, jwk: reshaped, host, expiry: '60s', deviceTransactionId: transactionId });
      expect(signed.status).toBe(400);
    }
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('/complete judges the session key by the signed SIWE, not a swapped body.jwk', async () => {
    const attackerJwk = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
    // An ordinary 60-second SIWE for the attacker's key, submitted under the
    // device transaction with the device key in body.jwk.
    const attacker = await post('/prepare', { keyId: keyRecord.id, jwk: attackerJwk, host, expiry: '60s' });
    expect(attacker.status).toBe(200);
    const attackerSignature = await account.signMessage({ message: attacker.body.prepared.siwe });
    const legacy = await post('/complete', { prepared: attacker.body.prepared, signature: attackerSignature, host, jwk, deviceTransactionId: transactionId });
    expect(legacy.status).toBe(400);

    // The device SIWE with another key swapped into body.jwk.
    const device = await prepare('60s', true);
    const signature = await account.signMessage({ message: device.body.prepared.siwe });
    const swapped = await post('/complete', { prepared: device.body.prepared, signature, host, jwk: attackerJwk, deviceTransactionId: transactionId });
    expect(swapped.status).toBe(400);
    expect(activateSessionWithHost).not.toHaveBeenCalled();

    // The matching key and SIWE complete and activate once.
    const ok = await post('/complete', { prepared: device.body.prepared, signature, host, jwk, deviceTransactionId: transactionId });
    expect(ok.status).toBe(200);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('versioned /complete reaches the device guard and refuses an overlong signed SIWE', async () => {
    // An ordinary (unnamed) 90-day prepare for the device key, then a
    // versioned /complete that names the transaction, echoing the prepared
    // object exactly as the web does. Only the device guard can refuse it.
    const prepared = await prepare('90d', false);
    expect(prepared.status).toBe(200);
    const signature = await account.signMessage({ message: prepared.body.prepared.siwe });
    const res = await post('/complete', {
      prepared: prepared.body.prepared,
      signature,
      host,
      jwk,
      protocolVersion: 1,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      deviceTransactionId: transactionId,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('delegation lifetime exceeds the device request');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('legacy /complete refuses decoy URI and Expiration Time lines in the SIWE separator slots', async () => {
    // Astra's repro: key B's canonical 90-day SIWE with the two separator
    // lines replaced by `URI: <device key>` and a 30 s `Expiration Time:`.
    // The positional parser behind the delegation still reads B and 90 days.
    const keyB = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
    const b = await post('/prepare', { keyId: keyRecord.id, jwk: keyB, host, expiry: '90d' });
    expect(b.status).toBe(200);
    const lines = (b.body.prepared.siwe as string).split('\n');
    expect(lines[2]).toBe('');
    expect(lines[4]).toBe('');
    lines[2] = `URI: ${sessionDidForPublicJwk(jwk)}`;
    lines[4] = `Expiration Time: ${new Date(Date.now() + 30_000).toISOString()}`;
    const decoy = lines.join('\n');
    const signature = await account.signMessage({ message: decoy });
    const res = await post('/complete', { prepared: { ...b.body.prepared, siwe: decoy }, signature, host, jwk, deviceTransactionId: transactionId });
    expect(res.status).toBe(400);
    expect(res.body.delegationHeader).toBeUndefined();
    const crlf = (b.body.prepared.siwe as string).replace(/\n/g, '\r\n');
    const crlfRes = await post('/complete', {
      prepared: { ...b.body.prepared, siwe: crlf },
      signature: await account.signMessage({ message: crlf }),
      host,
      jwk,
      deviceTransactionId: transactionId,
    });
    expect(crlfRes.status).toBe(400);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('authorize-sign routes refuse any request carrying deviceTransactionId', async () => {
    for (const id of [transactionId, 'unknown-transaction', null]) {
      for (const path of ['/authorize-sign-prepare', '/authorize-sign', '/authorize-sign-preview']) {
        const res = await post(path, { keyId: keyRecord.id, jwk, host: 'https://other.example', siwe: 'x', authorizationContextToken: 't', deviceTransactionId: id });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('device_transaction_unsupported');
      }
    }
    // Without the field the routes behave as before (their own validation).
    expect((await post('/authorize-sign-prepare', { keyId: keyRecord.id })).body.code).toBe('missing_authorize_sign_prepare_fields');
    expect((await post('/authorize-sign', {})).body.code).toBe('missing_authorization_context_token');
    expect((await post('/authorize-sign-preview', {})).body.code).toBe('missing_authorization_context_token');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});
