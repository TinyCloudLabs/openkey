
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
    '../routes/delegate?link-shorter-only-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?link-shorter-only-routes-isolated' as string
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
const lifetime = (prepared: { body: Record<string, any> }) => Date.parse(expiryLine(prepared.body.prepared.siwe)) - Date.now();
/** What the /delegate page sends after a pick: the pick as `expiry`, the link's own as `linkExpiry`. */
const pick = (expiry: string, link: string | undefined, extra: Record<string, unknown> = {}) =>
  post('/prepare', { keyId: externalKey.id, jwk, host, expiry, expiryChosen: true, ...(link === undefined ? {} : { linkExpiry: link }), ...extra });

describe('a /delegate link is shorter-only', () => {
  test('a pick longer than the link asked for is refused, with nothing prepared', async () => {
    const refused = await pick('30d', '7d');
    expect(refused.status).toBe(400);
    expect(refused.body.code).toBe('expiry_exceeds_link');
    expect(refused.body.prepared).toBeUndefined();
    expect((await pick('1y', '7d')).status).toBe(400);
    expect((await pick('604801s', '7d')).status).toBe(400);
  });

  test('the same time as the link, and any shorter one, are prepared at that length', async () => {
    for (const [expiry, days] of [['7d', 7], ['1d', 1], ['90m', 90 / 1440]] as const) {
      const prepared = await pick(expiry, '7d');
      expect(prepared.status, expiry).toBe(200);
      expect(lifetime(prepared)).toBeLessThanOrEqual(days * day);
      expect(lifetime(prepared)).toBeGreaterThan(days * day - 60_000);
    }
  });

  test('the ceiling is the link after the 30-day clamp', async () => {
    expect((await pick('30d', '365d')).status).toBe(200);
    expect((await pick('31d', '365d')).status).toBe(400);
  });

  test('a pick with no link expiry is held to the 7-day default', async () => {
    expect((await pick('7d', undefined)).status).toBe(200);
    expect((await pick('8d', undefined)).status).toBe(400);
  });

  test('a link that opts in with expiryChangeable lets a longer pick through, signed as picked', async () => {
    const prepared = await pick('31536000s', '7d', { expiryChangeable: true });
    expect(prepared.status).toBe(200);
    expect(lifetime(prepared)).toBeGreaterThan(365 * day - 60_000);
    const completed = await post('/complete', await webCompleteBody(prepared));
    expect(completed.status).toBe(200);
    expect(completed.body.expiresAt).toBe(expiryLine(prepared.body.prepared.siwe));
    // A shorter pick still works with the opt-in.
    expect((await pick('1d', '7d', { expiryChangeable: true })).status).toBe(200);
  });

  test('only a literal true opts in', async () => {
    for (const expiryChangeable of ['true', 1, 'yes', null]) {
      expect((await pick('1y', '7d', { expiryChangeable })).status).toBe(400);
    }
  });

  test('a link\'s own expiry with no pick is unchanged (still clamped to 30 days)', async () => {
    const plain = await post('/prepare', { keyId: externalKey.id, jwk, host, expiry: '365d' });
    expect(plain.status).toBe(200);
    expect(lifetime(plain)).toBeLessThanOrEqual(30 * day);
  });
});

describe('an empty request id is not a signed request', () => {
  test('null and empty approvalRequestId / deviceTransactionId do not skip the shorter-only check', async () => {
    for (const extra of [{ approvalRequestId: null }, { approvalRequestId: '' }, { deviceTransactionId: null }, { deviceTransactionId: '' }]) {
      const refused = await pick('30d', '7d', extra);
      expect(refused.body.code, JSON.stringify(extra)).toBe('expiry_exceeds_link');
    }
  });
});
