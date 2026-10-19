// TC-1483: the per-sign-in app record is wired into `/delegate` routes, and a
// failing or hanging metrics write never delays or fails the sign-in.

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
  appSignInDay: {
    upsert: mock(async (_args: unknown): Promise<unknown> => null),
    deleteMany: mock(async (_args: unknown): Promise<unknown> => null),
  },
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
    '../routes/delegate?app-sign-in-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?app-sign-in-routes-isolated' as string
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
  prisma.appSignInDay.upsert.mockReset();
  prisma.appSignInDay.upsert.mockImplementation(async () => null);
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

describe('app sign-in record on /delegate', () => {
  async function signIn(prepareExtra: Record<string, unknown> = {}) {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, ...prepareExtra });
    expect(prepared.status).toBe(200);
    return post('/complete', await webCompleteBody(prepared));
  }

  test('a successful sign-in records (user, origin, today)', async () => {
    const res = await signIn();
    expect(res.status).toBe(200);
    await Bun.sleep(0);
    expect(prisma.appSignInDay.upsert).toHaveBeenCalledTimes(1);
    const args = prisma.appSignInDay.upsert.mock.calls[0]![0] as { create: { userId: string; origin: string; day: Date } };
    const today = new Date();
    expect(args.create).toEqual({
      userId: user.id,
      origin: 'unknown', // no app origin bound at prepare
      day: new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate())),
    });
  });

  test('a throwing upsert still returns the delegation with 200', async () => {
    prisma.appSignInDay.upsert.mockImplementation(async () => { throw new Error('db down'); });
    const res = await signIn();
    expect(res.status).toBe(200);
    expect(res.body.delegationHeader?.Authorization).toBeString();
    await Bun.sleep(0);
    expect(prisma.appSignInDay.upsert).toHaveBeenCalledTimes(1);
  });

  test('a hanging upsert does not delay the response', async () => {
    prisma.appSignInDay.upsert.mockImplementation(() => new Promise(() => {}));
    const started = performance.now();
    const res = await signIn();
    expect(res.status).toBe(200);
    expect(res.body.delegationHeader?.Authorization).toBeString();
    expect(performance.now() - started).toBeLessThan(2000);
  });
});
