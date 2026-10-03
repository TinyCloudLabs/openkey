// TC-547: ordinary `/delegate` links (no device transaction). The web echoes
// the `/prepare` object to versioned `/complete` for wallet keys; ordinary
// lifetimes are capped; signing routes that cannot enforce a device
// transaction refuse `deviceTransactionId`.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';

const walletKey = '0x1111111111111111111111111111111111111111111111111111111111111111';
const wallet = privateKeyToAccount(walletKey);
const other = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
// An externally held wallet key: OpenKey never sees its private key.
const externalKey = {
  id: 'key_ext',
  userId: user.id,
  address: wallet.address,
  keyType: 'EXTERNAL',
  archivedAt: null,
  sealedBlob: null,
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async () => externalKey),
    findMany: mock(async () => [externalKey]),
    findUnique: mock(async () => externalKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
const unseal = mock(async () => walletKey);
const activateSessionWithHost = mock(async () => ({ success: true }));

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({
    deriveKey: mock(async () => new Uint8Array(32)),
    getQuote: mock(async () => 'quote'),
    isInTee: () => false,
  }),
  unseal,
  createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
  generatePrivateKey: () => walletKey,
  getAddressFromPrivateKey: () => wallet.address,
}));
mock.module('@tinycloud/sdk-core', () => ({ activateSessionWithHost }));
mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
    await next();
  }),
}));

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (and with an isolating query) so the route
  // binds the mocked database, TEE, and host activation.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?ordinary-link-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?ordinary-link-routes-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

beforeEach(() => {
  resetContexts?.();
  activateSessionWithHost.mockClear();
  unseal.mockClear();
});

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** The `/complete` body the web's external-wallet path sends. */
async function webCompleteBody(prepared: { body: Record<string, any> }, signer = wallet) {
  return {
    prepared: prepared.body.prepared,
    signature: await signer.signMessage({ message: prepared.body.prepared.siwe }),
    host,
    jwk,
    edited: false,
    authorizationContextToken: prepared.body.authorizationContext.token,
    selectedActionIds: prepared.body.selectedActionKeys,
  };
}

describe('versioned /complete for wallet keys', () => {
  test('approves the prepared object the web echoes back, bound to the signed SIWE address', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    expect(prepared.status).toBe(200);
    expect(prepared.body.prepared.address).toBeUndefined();

    const res = await post('/complete', await webCompleteBody(prepared));
    expect(res.status).toBe(200);
    expect(res.body.delegationHeader?.Authorization).toBeString();
    expect(res.body.address.toLowerCase()).toBe(wallet.address.toLowerCase());
    expect(res.body.ownerDid.toLowerCase()).toBe(`did:pkh:eip155:1:${wallet.address}`.toLowerCase());
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);

    // The context is single-use.
    const replay = await post('/complete', await webCompleteBody(prepared));
    expect(replay.status).toBe(400);
  });

  test('refuses a prepared.address that disagrees with the signed SIWE', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    const body = await webCompleteBody(prepared);
    const res = await post('/complete', { ...body, prepared: { ...body.prepared, address: other.address } });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('key-mismatch');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('refuses a SIWE prepared for another key under this context', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    const forged = prepared.body.prepared.siwe.replace(wallet.address, other.address);
    const res = await post('/complete', {
      ...(await webCompleteBody(prepared)),
      prepared: { ...prepared.body.prepared, siwe: forged },
      signature: await other.signMessage({ message: forged }),
    });
    expect(res.status).toBe(400);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('refuses a signature from another wallet without consuming the context or activating', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    const wrongWallet = await post('/complete', await webCompleteBody(prepared, other));
    expect(wrongWallet.status).toBe(400);
    expect(wrongWallet.body.code).toBe('signature-mismatch');
    expect(wrongWallet.body.delegationHeader).toBeUndefined();
    const garbage = await post('/complete', { ...(await webCompleteBody(prepared)), signature: '0x1234' });
    expect(garbage.status).toBe(400);
    expect(activateSessionWithHost).not.toHaveBeenCalled();

    // The context is still unused: the right wallet can complete it.
    const ok = await post('/complete', await webCompleteBody(prepared));
    expect(ok.status).toBe(200);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('reports the signed SIWE expiry, ignoring caller-supplied expiry metadata', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, expiry: '1h' });
    const signedExpiry = /^Expiration Time: (.+)$/m.exec(prepared.body.prepared.siwe)?.[1];
    const body = await webCompleteBody(prepared);
    const res = await post('/complete', {
      ...body,
      prepared: { ...body.prepared, expirationTime: '2099-01-01T00:00:00.000Z' },
    });
    expect(res.status).toBe(200);
    expect(signedExpiry).toBeString();
    expect(res.body.expirationTime).toBe(signedExpiry);
    expect(res.body.expiresAt).toBe(signedExpiry);
    expect(res.body.expiry).toBe(signedExpiry);
  });
});

describe('ordinary delegation lifetime', () => {
  test('/prepare caps a requested lifetime at 30 days and keeps shorter ones', async () => {
    const expiresIn = async (expiry: string) => {
      const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, expiry });
      expect(prepared.status).toBe(200);
      const line = /^Expiration Time: (.+)$/m.exec(prepared.body.prepared.siwe)?.[1];
      return Date.parse(line ?? '') - Date.now();
    };
    const day = 24 * 60 * 60 * 1000;
    const capped = await expiresIn('90d');
    expect(capped).toBeLessThanOrEqual(30 * day);
    expect(capped).toBeGreaterThan(30 * day - 60_000);
    const hour = await expiresIn('1h');
    expect(hour).toBeLessThanOrEqual(60 * 60 * 1000);
    expect(hour).toBeGreaterThan(60 * 60 * 1000 - 60_000);
  });
});

describe('signing routes without device enforcement', () => {
  test('/sign and /host refuse deviceTransactionId before signing', async () => {
    const sign = await post('/sign', {
      address: wallet.address,
      chainId: 1,
      message: 'hello',
      type: 'siwe',
      deviceTransactionId: 'unknown-transaction',
    });
    expect(sign.status).toBe(400);
    expect(sign.body).toMatchObject({ approved: false, code: 'device_transaction_unsupported' });

    const hostSign = await post('/host', {
      keyId: externalKey.id,
      peerId: 'peer',
      space: 'default',
      deviceTransactionId: 'unknown-transaction',
    });
    expect(hostSign.status).toBe(400);
    expect(hostSign.body.code).toBe('device_transaction_unsupported');
    expect(unseal).not.toHaveBeenCalled();
  });
});
