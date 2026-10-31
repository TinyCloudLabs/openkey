
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { mockModules, replaceModules } from './mock-module';

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

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({
      deriveKey: mock(async () => new Uint8Array(32)),
      getQuote: mock(async () => 'quote'),
      isInTee: () => false,
    }),
    unseal,
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => walletKey,
    getAddressFromPrivateKey: () => wallet.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (and with an isolating query) so the route
  // binds the mocked database, TEE, and host activation.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?expiry-choice-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?expiry-choice-routes-isolated' as string
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
const day = 24 * 60 * 60 * 1000;
const expiryLine = (siwe: string) => /^Expiration Time: (.+)$/m.exec(siwe)?.[1] ?? '';
async function prepareWith(extra: Record<string, unknown>) {
  return post('/prepare', { keyId: externalKey.id, jwk, host, ...extra });
}
const lifetime = (prepared: { body: Record<string, any> }) => Date.parse(expiryLine(prepared.body.prepared.siwe)) - Date.now();

describe('a link-supplied expiry is clamped, a user-picked one is not', () => {
  test('a link asking for a year (365d) gets 30 days', async () => {
    const prepared = await prepareWith({ expiry: '365d' });
    expect(prepared.status).toBe(200);
    expect(lifetime(prepared)).toBeLessThanOrEqual(30 * day);
    expect(lifetime(prepared)).toBeGreaterThan(30 * day - 60_000);
  });

  test('a user pick of a year signs a year, and the grant reports the signed time', async () => {
    const prepared = await prepareWith({ expiry: '31536000s', expiryChosen: true });
    expect(prepared.status).toBe(200);
    expect(lifetime(prepared)).toBeGreaterThan(365 * day - 60_000);
    expect(lifetime(prepared)).toBeLessThanOrEqual(365 * day);
    const signedExpiry = expiryLine(prepared.body.prepared.siwe);
    const res = await post('/complete', await webCompleteBody(prepared));
    expect(res.status).toBe(200);
    expect(res.body.expiresAt).toBe(signedExpiry);
  });

  test('only a literal true counts as a user pick', async () => {
    for (const expiryChosen of ['true', 1, 'yes']) {
      const prepared = await prepareWith({ expiry: '365d', expiryChosen });
      expect(lifetime(prepared)).toBeLessThanOrEqual(30 * day);
    }
  });

  test('a user pick keeps the one-minute floor and refuses a time no SIWE can hold', async () => {
    const short = await prepareWith({ expiry: '5s', expiryChosen: true });
    expect(lifetime(short)).toBeGreaterThan(60_000 - 5_000);
    expect(lifetime(short)).toBeLessThanOrEqual(60_000);
    const absurd = await prepareWith({ expiry: '9999999999999s', expiryChosen: true });
    expect(absurd.status).toBe(400);
    expect(absurd.body.code).toBe('invalid_expiry');
  });
});
