// TC-1854: `/delegate` routes refuse permission entries that carry a caveats
// restriction or a per-entry expiry, on every route that accepts permissions[].
// The refusal happens before any session is activated.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import { mockModules, replaceModules } from './mock-module';

const walletKey = '0x1111111111111111111111111111111111111111111111111111111111111111';
const wallet = privateKeyToAccount(walletKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const keyBase = { userId: user.id, address: wallet.address, archivedAt: null, sealingContext: null };
const managedKey = { ...keyBase, id: 'key_managed', keyType: 'MANAGED', sealedBlob: 'sealed-blob' };
const externalKey = { ...keyBase, id: 'key_ext', keyType: 'EXTERNAL', sealedBlob: null };
const keys = [managedKey, externalKey];

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id?: string } }) => keys.find((key) => key.id === where.id) ?? null),
    findMany: mock(async () => keys),
    findUnique: mock(async () => managedKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
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
    unseal: mock(async () => walletKey),
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => walletKey,
    getAddressFromPrivateKey: () => wallet.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
});

let router: typeof delegateRouter;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (with an isolating query) so the route binds the mocks above.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?permission-refusal-routes-isolated' as string
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
  activateSessionWithHost.mockClear();
});

const space = `tinycloud:pkh:eip155:1:${wallet.address}:secrets`;
const kvGet = { service: 'tinycloud.kv', space, path: 'vault/secrets/TC_FWD_TOKEN', actions: ['tinycloud.kv/get'] };

const refusedEntries: Array<[string, unknown[]]> = [
  ['caveats', [{ ...kvGet, caveats: [{ maxSize: 1 }] }]],
  ['expiry', [{ ...kvGet, expiry: 1700000000 }]],
  ['expiryMs', [{ ...kvGet, expiryMs: 1700000000000 }]],
  ['expiryMs null', [{ ...kvGet, expiryMs: null }]],
];

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

describe('POST / refuses permission entries it cannot carry', () => {
  test.each(refusedEntries)('refuses %s', async (_label, permissions) => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('invalid_permissions');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});

describe('POST /prepare refuses permission entries it cannot carry', () => {
  test.each(refusedEntries)('refuses %s', async (_label, permissions) => {
    const res = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('invalid_permissions');
  });
});

describe('POST /complete refuses permission entries it cannot carry', () => {
  test.each(refusedEntries)('refuses %s', async (_label, permissions) => {
    const res = await post('/complete', {
      prepared: {},
      signature: '0xsignature',
      host,
      jwk,
      permissions,
    });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('invalid_permissions');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});
