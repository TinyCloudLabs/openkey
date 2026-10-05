// TC-703: every delegation `/delegate` hands back to the CLI (callback, paste
// code, device relay) is the `/api/delegate` or `/api/delegate/complete`
// response. Each states `primary`: whether the key that signed is the
// user's primary key, decided from the database, never from the request.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';

const primaryPrivateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const secondaryPrivateKey = '0x3333333333333333333333333333333333333333333333333333333333333333';
const primaryAccount = privateKeyToAccount(primaryPrivateKey);
const secondaryAccount = privateKeyToAccount(secondaryPrivateKey);
const wallet = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');
const stranger = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';

const managed = (id: string, address: string, sealedBlob: string, isCanonicalTinyCloud: boolean) => ({
  id, userId: user.id, address, keyType: 'MANAGED', isCanonicalTinyCloud, archivedAt: null, sealedBlob, sealingContext: null,
});
const primaryKey = managed('key_primary', primaryAccount.address, 'sealed-primary', true);
const secondaryKey = managed('key_secondary', secondaryAccount.address, 'sealed-secondary', false);
// Stored as the wallet reported it (lowercase); the SIWE carries EIP-55.
const externalKey = {
  id: 'key_external', userId: user.id, address: wallet.address.toLowerCase(), keyType: 'EXTERNAL',
  isCanonicalTinyCloud: false, archivedAt: null, sealedBlob: null, sealingContext: null,
};
const keys = [primaryKey, secondaryKey, externalKey];

type Where = { id?: string; userId?: string; archivedAt?: null; address?: { equals: string; mode: string } };
const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Where }) => keys.find((key) =>
      key.userId === where.userId &&
      key.archivedAt === null &&
      (where.id === undefined || key.id === where.id) &&
      (where.address === undefined || key.address.toLowerCase() === where.address.equals.toLowerCase()),
    ) ?? null),
    findMany: mock(async () => keys),
    findUnique: mock(async () => null),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({
    deriveKey: mock(async () => new Uint8Array(32)),
    getQuote: mock(async () => 'quote'),
    isInTee: () => false,
  }),
  unseal: mock(async (sealedBlob: string) => sealedBlob === 'sealed-primary' ? primaryPrivateKey : secondaryPrivateKey),
  createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
  generatePrivateKey: () => primaryPrivateKey,
  getAddressFromPrivateKey: () => primaryAccount.address,
}));
mock.module('@tinycloud/sdk-core', () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }));
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
  ({ delegateRouter: router } = await import('../routes/delegate?primary-flag-routes-isolated' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?primary-flag-routes-isolated' as string
  ));
});

beforeEach(() => {
  resetContexts?.();
});

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function prepare(keyId: string) {
  const prepared = await post('/prepare', { keyId, jwk, host });
  expect(prepared.status).toBe(200);
  return prepared.body;
}

/** The managed approval the web sends after the consent screen. */
async function approveManaged(keyId: string) {
  const prepared = await prepare(keyId);
  return post('/', {
    keyId, jwk, host, prefix: 'default',
    prepared: prepared.prepared,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
    protocolVersion: 1,
  });
}

/** The wallet completion the web sends, signed by `signer`. */
async function completeWith(keyId: string, signer: typeof wallet) {
  const prepared = await prepare(keyId);
  return post('/complete', {
    prepared: prepared.prepared,
    signature: await signer.signMessage({ message: prepared.prepared.siwe }),
    host, jwk, edited: false, protocolVersion: 1,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
  });
}

describe('primary flag on managed delegations (POST /api/delegate)', () => {
  test('is true when the primary key signs', async () => {
    const res = await approveManaged(primaryKey.id);
    expect(res.status).toBe(200);
    expect(res.body.address).toBe(primaryAccount.address);
    expect(res.body.primary).toBe(true);
  });

  test('is false when another managed key signs', async () => {
    const res = await approveManaged(secondaryKey.id);
    expect(res.status).toBe(200);
    expect(res.body.address).toBe(secondaryAccount.address);
    expect(res.body.primary).toBe(false);
  });

  test('the legacy token-less path states it too', async () => {
    const primary = await post('/', { keyId: primaryKey.id, jwk, host });
    const secondary = await post('/', { keyId: secondaryKey.id, jwk, host });
    expect(primary.status).toBe(200);
    expect(secondary.status).toBe(200);
    expect(primary.body.primary).toBe(true);
    expect(secondary.body.primary).toBe(false);
  });

  test('a caller cannot claim primary through the request body', async () => {
    const prepared = await prepare(secondaryKey.id);
    const res = await post('/', {
      keyId: secondaryKey.id, jwk, host, primary: true,
      prepared: { ...prepared.prepared, primary: true },
      authorizationContextToken: prepared.authorizationContext.token,
      selectedActionIds: prepared.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(res.status).toBe(200);
    expect(res.body.primary).toBe(false);
  });
});

describe('primary flag on wallet delegations (POST /api/delegate/complete)', () => {
  test('is false for an external wallet', async () => {
    const res = await completeWith(externalKey.id, wallet);
    expect(res.status).toBe(200);
    expect(res.body.address).toBe(wallet.address);
    expect(res.body.primary).toBe(false);
  });

  test('is read from the signing address, not assumed false', async () => {
    // Only the database record makes this signer primary.
    const res = await completeWith(primaryKey.id, primaryAccount);
    expect(res.status).toBe(200);
    expect(res.body.primary).toBe(true);
  });

  test('is false for a signer this user does not hold', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    const siwe = (prepared.body.prepared.siwe as string).replace(wallet.address, stranger.address);
    const res = await post('/complete', {
      prepared: { ...prepared.body.prepared, siwe },
      signature: await stranger.signMessage({ message: siwe }),
      host, jwk, edited: false, primary: true,
    });
    expect(res.status).toBe(200);
    expect(res.body.primary).toBe(false);
  });
});
