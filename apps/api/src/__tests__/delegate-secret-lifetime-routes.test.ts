// TC-3800: on the /delegate popup and a pasted link (/prepare, /complete) a grant that may `decrypt` or `key.create`
// on a key or prefix under `default/secrets/` lasts 7 days at most, whether the link or the owner asked for more:
// /prepare brings the expiry back to 7 days, and /complete refuses signed bytes that still ask for more. A whole
// network's `decrypt` is held the same way only while `OPENKEY_NETWORK_DECRYPT_CAP=enabled`.

import { afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { mockModules, replaceModules } from './mock-module';

const walletKey = '0x1111111111111111111111111111111111111111111111111111111111111111';
const wallet = privateKeyToAccount(walletKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const OWNER = `did:pkh:eip155:1:${wallet.address}`;
const SPACE = `tinycloud:pkh:eip155:1:${wallet.address}:default`;
const keyUrn = (tail: string) => `urn:tinycloud:encryption:${OWNER}:default${tail}`;
const DECRYPT = 'tinycloud.encryption/decrypt';
const CREATE = 'tinycloud.encryption/key.create';
const DAY_MS = 86_400_000;
// An externally held wallet key: OpenKey never sees its private key.
const externalKey = {
  id: 'key_ext', userId: user.id, address: wallet.address, keyType: 'EXTERNAL', archivedAt: null, sealedBlob: null, sealingContext: null,
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
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => walletKey),
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => walletKey,
    getAddressFromPrivateKey: () => wallet.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (and with an isolating query) so the route binds the mocked database and TEE.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?delegate-secret-lifetime-routes' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?delegate-secret-lifetime-routes' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

beforeEach(() => resetContexts?.());
afterEach(() => {
  delete process.env.OPENKEY_NETWORK_DECRYPT_CAP;
});

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

function permissionsFor(path: string, actions: string[]) {
  return [
    { service: 'tinycloud.kv', space: SPACE, path: 'notes/', actions: ['tinycloud.kv/get'] },
    { service: 'tinycloud.encryption', space: 'encryption', path, actions },
  ];
}
const expiryLine = (siwe: string) => /^Expiration Time: (.+)$/m.exec(siwe)?.[1] ?? '';
const lifetime = (prepared: { body: Record<string, any> }) => Date.parse(expiryLine(prepared.body.prepared.siwe)) - Date.now();
async function prepareWith(permissions: unknown, extra: Record<string, unknown>) {
  const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions, ...extra });
  expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
  return prepared;
}
async function completeBody(prepared: { body: Record<string, any> }, permissions: unknown) {
  return {
    permissions,
    prepared: prepared.body.prepared,
    signature: await wallet.signMessage({ message: prepared.body.prepared.siwe }),
    host,
    jwk,
    edited: false,
    authorizationContextToken: prepared.body.authorizationContext.token,
    selectedActionIds: prepared.body.selectedActionKeys,
  };
}
function expectSevenDays(prepared: { body: Record<string, any> }) {
  expect(lifetime(prepared)).toBeLessThanOrEqual(7 * DAY_MS);
  expect(lifetime(prepared)).toBeGreaterThan(7 * DAY_MS - 60_000);
}

const SECRET_SHAPES: Array<[string, string, string[]]> = [
  ["decrypt on one secret's key", keyUrn('/secrets/openai_api_key'), [DECRYPT]],
  ['decrypt and key.create on a scoped secret key', keyUrn('/secrets/scoped/work/api_key'), [DECRYPT, CREATE]],
];

describe('/prepare holds a grant on secret keys to 7 days', () => {
  test.each(SECRET_SHAPES)("%s: a link's 30 days become 7", async (_name, path, actions) => {
    expectSevenDays(await prepareWith(permissionsFor(path, actions), { expiry: '30d' }));
  });

  test.each(SECRET_SHAPES)("%s: the owner's year becomes 7 days, and /complete signs it", async (_name, path, actions) => {
    const prepared = await prepareWith(permissionsFor(path, actions), { expiry: '31536000s', expiryChosen: true, expiryChangeable: true });
    expectSevenDays(prepared);
    const res = await post('/complete', await completeBody(prepared, permissionsFor(path, actions)));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.expiresAt).toBe(expiryLine(prepared.body.prepared.siwe));
  });

  test("the owner's 2 days stay 2 days", async () => {
    const prepared = await prepareWith(permissionsFor(SECRET_SHAPES[0]![1], [DECRYPT]), { expiry: '2d', expiryChosen: true });
    expect(lifetime(prepared)).toBeLessThanOrEqual(2 * DAY_MS);
    expect(lifetime(prepared)).toBeGreaterThan(2 * DAY_MS - 60_000);
  });
});

describe('a whole network decrypt follows OPENKEY_NETWORK_DECRYPT_CAP', () => {
  const network = permissionsFor(keyUrn(''), [DECRYPT]);

  test("off (the default): a link's 30 days are kept and /complete signs them", async () => {
    const prepared = await prepareWith(network, { expiry: '30d' });
    expect(lifetime(prepared)).toBeGreaterThan(29 * DAY_MS);
    expect((await post('/complete', await completeBody(prepared, network))).status).toBe(200);
  });

  test("enabled: a link's 30 days become 7", async () => {
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    expectSevenDays(await prepareWith(network, { expiry: '30d' }));
  });

  test('enabled after /prepare: /complete refuses the 30 days already signed', async () => {
    const prepared = await prepareWith(network, { expiry: '30d' });
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    const res = await post('/complete', await completeBody(prepared, network));
    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      error: 'Access to your secrets can last up to 7 days. Ask again with an expiry of 7 days or less.',
      code: 'secret_lifetime_exceeded',
    });
  });
});
