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
// An externally held wallet key (OpenKey never sees its private key), and a managed key OpenKey signs with.
const keyBase = { userId: user.id, address: wallet.address, archivedAt: null, sealingContext: null };
const externalKey = { ...keyBase, id: 'key_ext', keyType: 'EXTERNAL', sealedBlob: null };
const managedKey = { ...keyBase, id: 'key_managed', keyType: 'MANAGED', sealedBlob: 'sealed-blob' };
const keys = [externalKey, managedKey];

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id?: string } }) => keys.find((key) => key.id === where.id) ?? null),
    findMany: mock(async () => keys),
    findUnique: mock(async () => managedKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
const signedByOpenKey: string[] = [];

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
  '../services/tinycloud-bootstrap': () => ({ ensureTinyCloudBootstrap: mock(async () => ({ status: 'complete' as const })) }),
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => walletKey),
    createWalletFromPrivateKey: (key: string) => {
      const account = privateKeyToAccount(key as `0x${string}`);
      return {
        ...account,
        signMessage: async (args: { message: string }) => {
          signedByOpenKey.push(args.message);
          return account.signMessage(args);
        },
      };
    },
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

beforeEach(() => {
  resetContexts?.();
  signedByOpenKey.length = 0;
});
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
async function prepareWith(permissions: unknown, extra: Record<string, unknown>, keyId = externalKey.id) {
  const prepared = await post('/prepare', { keyId, jwk, host, permissions, ...extra });
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
const signedLifetime = (siwe: string) => Date.parse(expiryLine(siwe)) - Date.now();

const SECRET_REFUSED = {
  error: 'This request asks for secret access longer than 7 days. Secret access lasts at most 7 days, so ask again with an expiry of 7 days or less.',
  code: 'secret_lifetime_exceeded',
};
const NETWORK_REFUSED = {
  error: 'This request asks for access to secrets or encrypted data longer than 7 days. Access to secrets or encrypted data lasts at most 7 days, so ask again with an expiry of 7 days or less.',
  code: 'secret_lifetime_exceeded',
};

// The popup and link accept only a secret's own key under `secrets/` (the prefix itself is refused there).
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

describe('/complete refuses signed bytes that ask for more than 7 days on secret keys', () => {
  test.each(SECRET_SHAPES)('%s: a wallet signature over 30 days is refused', async (_name, path, actions) => {
    const permissions = permissionsFor(path, actions);
    const prepared = await prepareWith(permissions, { expiry: '2d', expiryChosen: true });
    const longer = prepared.body.prepared.siwe.replace(
      /^Expiration Time: .+$/m,
      `Expiration Time: ${new Date(Date.now() + 30 * DAY_MS).toISOString()}`,
    );
    const tampered = { body: { ...prepared.body, prepared: { ...prepared.body.prepared, siwe: longer } } };
    const res = await post('/complete', await completeBody(tampered, permissions));
    expect(res.status).toBe(400);
    expect(res.body).toEqual(SECRET_REFUSED);
  });
});

describe('the managed POST /delegate', () => {
  const managed = (body: Record<string, unknown>) => post('/', { keyId: managedKey.id, jwk, host, ...body });

  test.each(SECRET_SHAPES)("%s (legacy): a link's 30 days and the owner's year are signed as 7 days", async (_name, path, actions) => {
    for (const extra of [{ expiry: '30d' }, { expiry: '31536000s', expiryChosen: true, expiryChangeable: true }]) {
      const res = await managed({ permissions: permissionsFor(path, actions), ...extra });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(signedLifetime(res.body.signedMessage)).toBeLessThanOrEqual(7 * DAY_MS);
      expect(signedLifetime(res.body.signedMessage)).toBeGreaterThan(7 * DAY_MS - 60_000);
    }
  });

  test('legacy, whole network decrypt: 30 days with the network cap off, 7 with it on', async () => {
    const network = permissionsFor(keyUrn(''), [DECRYPT]);
    const off = await managed({ permissions: network, expiry: '30d' });
    expect(off.status, JSON.stringify(off.body)).toBe(200);
    expect(signedLifetime(off.body.signedMessage)).toBeGreaterThan(29 * DAY_MS);
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    const on = await managed({ permissions: network, expiry: '30d' });
    expect(on.status, JSON.stringify(on.body)).toBe(200);
    expect(signedLifetime(on.body.signedMessage)).toBeLessThanOrEqual(7 * DAY_MS);
  });

  test.each(SECRET_SHAPES)('%s (versioned): the prepared 7 days are signed', async (_name, path, actions) => {
    const permissions = permissionsFor(path, actions);
    const prepared = await prepareWith(permissions, { expiry: '30d' }, managedKey.id);
    const res = await managed({
      permissions,
      prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(signedLifetime(res.body.signedMessage)).toBeLessThanOrEqual(7 * DAY_MS);
  });

  test('versioned, whole network decrypt prepared for 30 days, then the network cap turned on: refused, nothing signed', async () => {
    const network = permissionsFor(keyUrn(''), [DECRYPT]);
    const prepared = await prepareWith(network, { expiry: '30d' }, managedKey.id);
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    const res = await managed({
      permissions: network,
      prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(res.status).toBe(400);
    expect(res.body).toEqual(NETWORK_REFUSED);
    expect(signedByOpenKey).toEqual([]);
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
    expect(res.body).toEqual(NETWORK_REFUSED);
  });
});

// A read of the secrets vault in the KV store (a secret's sealed value, a scope, the whole vault, the names) is held to
// 7 days like a grant on secret keys, on every path, with no flag.
const kvVaultPermissions = (path: string, ability = 'tinycloud.kv/get') => [
  { service: 'tinycloud.kv', space: SPACE, path: 'notes/', actions: ['tinycloud.kv/get'] },
  { service: 'tinycloud.kv', space: SPACE, path, actions: [ability] },
];
const KV_VAULT_SHAPES: Array<[string, ReturnType<typeof kvVaultPermissions>]> = [
  ['get on one secret', kvVaultPermissions('vault/secrets/OPENAI_API_KEY')],
  ['get on a scoped secret', kvVaultPermissions('vault/secrets/scoped/work/API_KEY')],
  ['get on the whole vault', kvVaultPermissions('vault/secrets/')],
  ['list on the whole vault', kvVaultPermissions('vault/secrets/', 'tinycloud.kv/list')],
];

describe('a KV read of the secrets vault is held to 7 days', () => {
  test.each(KV_VAULT_SHAPES)("%s: /prepare turns a link's 30 days and the owner's year into 7, and /complete signs it", async (_name, permissions) => {
    expectSevenDays(await prepareWith(permissions, { expiry: '30d' }));
    const prepared = await prepareWith(permissions, { expiry: '31536000s', expiryChosen: true, expiryChangeable: true });
    expectSevenDays(prepared);
    const res = await post('/complete', await completeBody(prepared, permissions));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.expiresAt).toBe(expiryLine(prepared.body.prepared.siwe));
  });

  test.each(KV_VAULT_SHAPES)('%s: /complete refuses a wallet signature over 30 days', async (_name, permissions) => {
    const prepared = await prepareWith(permissions, { expiry: '2d', expiryChosen: true });
    const longer = prepared.body.prepared.siwe.replace(
      /^Expiration Time: .+$/m,
      `Expiration Time: ${new Date(Date.now() + 30 * DAY_MS).toISOString()}`,
    );
    const tampered = { body: { ...prepared.body, prepared: { ...prepared.body.prepared, siwe: longer } } };
    const res = await post('/complete', await completeBody(tampered, permissions));
    expect(res.status).toBe(400);
    expect(res.body).toEqual(SECRET_REFUSED);
  });

  test.each(KV_VAULT_SHAPES)('%s: the managed POST /delegate signs 7 days, legacy and versioned', async (_name, permissions) => {
    const managed = (body: Record<string, unknown>) => post('/', { keyId: managedKey.id, jwk, host, ...body });
    const legacy = await managed({ permissions, expiry: '30d' });
    expect(legacy.status, JSON.stringify(legacy.body)).toBe(200);
    expect(signedLifetime(legacy.body.signedMessage)).toBeLessThanOrEqual(7 * DAY_MS);
    expect(signedLifetime(legacy.body.signedMessage)).toBeGreaterThan(7 * DAY_MS - 60_000);
    const prepared = await prepareWith(permissions, { expiry: '30d' }, managedKey.id);
    const versioned = await managed({
      permissions,
      prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(versioned.status, JSON.stringify(versioned.body)).toBe(200);
    expect(signedLifetime(versioned.body.signedMessage)).toBeLessThanOrEqual(7 * DAY_MS);
  });

  test('a read of another folder keeps the 30 days', async () => {
    expect(lifetime(await prepareWith(kvVaultPermissions('notes/a'), { expiry: '30d' }))).toBeGreaterThan(29 * DAY_MS);
  });
});
