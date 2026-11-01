// Route-level checks that /authorize-sign-prepare, /authorize-sign-preview and
// /authorize-sign refuse `apps/` key resources and `key.delete` before a
// context is issued, a preview is approved or a signature is made.
//
// A preview or a signature for an `apps/` message needs a context that was
// issued for one. Nothing issues such a context, so these tests lift the
// refusal while the context and the preview approval are issued
// (`allowAppKeys`), then restore it and call the route under test.

import './tc1777-test-env';
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const ORIGIN = 'https://listen.tinycloud.xyz';
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;

let signed: string[] = [];
let allowAppKeys = false;
let manifestBindResult: { ok: boolean; manifest?: Record<string, unknown>; fetchedDigest?: string; reason?: string } = {
  ok: true,
  fetchedDigest: 'a'.repeat(64),
  manifest: { name: 'Listen', appId: 'xyz.tinycloud.listen', prefix: 'xyz.tinycloud.listen' },
};
const fetchAndBindWellKnownManifest = mock(async () => manifestBindResult);

const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== user.id) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
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
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return {
        ...wallet,
        signMessage: async (args: { message: string }) => {
          signed.push(args.message);
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }),
  '../services/manifest-origin-fetch': () => ({ fetchAndBindWellKnownManifest }),
  '../services/app-key-refusal': (actual) => ({
    appKeyRefusalForSiwe: (...args: Parameters<typeof actual.appKeyRefusalForSiwe>) =>
      allowAppKeys ? null : actual.appKeyRefusalForSiwe(...args),
  }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];

beforeAll(async () => {
  ({ delegateRouter: router } = await import('../routes/delegate?app-key-refusal-authorize-sign' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?app-key-refusal-authorize-sign' as string
  ));
});

beforeEach(() => {
  signed = [];
  allowAppKeys = false;
  manifestBindResult = {
    ok: true,
    fetchedDigest: 'a'.repeat(64),
    manifest: { name: 'Listen', appId: 'xyz.tinycloud.listen', prefix: 'xyz.tinycloud.listen' },
  };
  fetchAndBindWellKnownManifest.mockClear();
  resetContexts?.();
});

function siweWith(rawAbilities: Record<string, string[]> = {}): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: 'listen.tinycloud.xyz',
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: SPACE,
    jwk,
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get', 'tinycloud.kv/put'] } } as never,
    ...(Object.keys(rawAbilities).length > 0 ? { rawAbilities } : {}),
  }).siwe;
}

const APPS_KEY = { [urn('/apps/xyz.tinycloud.listen/k')]: ['tinycloud.encryption/decrypt', 'tinycloud.encryption/key.create'] };
const APPS_PREFIX = { [urn('/apps/xyz.tinycloud.listen/')]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] };

function post(path: string, body: unknown) {
  return router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function prepareBody(siwe: unknown) {
  return {
    keyId: keyRecord.id,
    siwe,
    jwk,
    host: 'https://node.tinycloud.xyz',
    requestOrigin: ORIGIN,
    reportedOrigin: ORIGIN,
    presentation: { manifestDigest: 'a'.repeat(64), displayName: 'Listen' },
  };
}

const NOT_DECLARED = "This website doesn't list the key this app asked for, so OpenKey didn't approve it.";
const KEY_DELETE = "Apps can't be given permission to delete keys, so OpenKey didn't approve this request.";

describe('POST /authorize-sign-prepare', () => {
  test.each([
    ['an exact app key', APPS_KEY],
    ['an app prefix', APPS_PREFIX],
  ])('refuses %s from a site whose manifest and origin match, and issues nothing', async (_name, raw) => {
    const res = await post('/authorize-sign-prepare', prepareBody(siweWith(raw)));
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual({ error: NOT_DECLARED, code: 'app_key_grant_refused' });
    expect(signed).toEqual([]);
  });

  test('refuses key.delete on a key outside apps/', async () => {
    const res = await post('/authorize-sign-prepare', prepareBody(siweWith({ [urn('/secrets/x')]: ['tinycloud.encryption/key.delete'] })));
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual({ error: KEY_DELETE, code: 'key_delete_not_grantable' });
  });

  test('refuses an apps/ key written with a capital letter in the first segment', async () => {
    const res = await post('/authorize-sign-prepare', prepareBody(siweWith({ [urn('/Apps/x/y')]: ['tinycloud.encryption/decrypt'] })));
    expect(res.status).toBe(403);
  });

  test('refuses a ReCap that cannot be read exactly', async () => {
    const siwe = siweWith().replace(/(- urn:recap:)\S*/, `$1${Buffer.from('{"att":{},"att":{}}').toString('base64url')}`);
    const res = await post('/authorize-sign-prepare', prepareBody(siwe));
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ code: 'invalid_siwe_recap' });
  });

  test.each([
    ['an object', { not: 'a string' }],
    ['an array', ['x']],
    ['a number', 7],
  ])('answers 400 when siwe is %s', async (_name, siwe) => {
    const res = await post('/authorize-sign-prepare', prepareBody(siwe));
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ code: 'invalid_siwe' });
  });

  test('still issues a context for a message with no app keys', async () => {
    const res = await post('/authorize-sign-prepare', { ...prepareBody(siweWith({})), requestOrigin: ORIGIN });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({ authorizationContextToken: expect.stringMatching(/^oks_/) });
  });

  // TC-2247: a website's sign-in may not name decrypt outside its own apps/ prefix, the bare network included.
  test.each([
    ['default-network decrypt', { [urn('')]: ['tinycloud.encryption/decrypt', 'tinycloud.encryption/network.create'] }],
    ['decrypt on a key outside apps/', { [urn('/appsx/y')]: ['tinycloud.encryption/decrypt'] }],
  ])('refuses %s and issues nothing', async (_name, raw) => {
    const res = await post('/authorize-sign-prepare', { ...prepareBody(siweWith(raw)), requestOrigin: ORIGIN });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual({ error: NOT_DECLARED, code: 'app_key_grant_refused' });
    expect(signed).toEqual([]);
  });
});

describe('POST /authorize-sign-preview and /authorize-sign for a context bound to an apps/ message', () => {
  async function contextFor(raw: Record<string, string[]>) {
    allowAppKeys = true;
    const prepared = await post('/authorize-sign-prepare', prepareBody(siweWith(raw)));
    expect(prepared.status).toBe(200);
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as {
      authorizationContextToken: string;
      allowedActionIds: string[];
    };
    return { token: authorizationContextToken, allowed: allowedActionIds };
  }

  test.each([
    ['an exact app key', APPS_KEY],
    ['an app prefix', APPS_PREFIX],
  ])('preview refuses %s', async (_name, raw) => {
    const { token, allowed } = await contextFor(raw);
    allowAppKeys = false;
    const res = await post('/authorize-sign-preview', { authorizationContextToken: token, selectedActionIds: allowed });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual({ error: NOT_DECLARED, code: 'app_key_grant_refused' });
  });

  test.each([
    ['an exact app key', APPS_KEY],
    ['an app prefix', APPS_PREFIX],
  ])('sign refuses %s before the context is used and before anything is signed', async (_name, raw) => {
    const { token, allowed } = await contextFor(raw);
    // The preview approval is obtained while the refusal is lifted.
    const preview = await post('/authorize-sign-preview', { authorizationContextToken: token, selectedActionIds: allowed });
    expect(preview.status).toBe(200);
    const { previewApprovalToken } = await preview.json() as { previewApprovalToken: string };

    allowAppKeys = false;
    const body = { authorizationContextToken: token, previewApprovalToken, selectedActionIds: allowed, protocolVersion: 1 };
    const res = await post('/authorize-sign', body);
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual({ error: NOT_DECLARED, code: 'app_key_grant_refused' });
    expect(signed).toEqual([]);

    // The refusal came before the context was consumed: with the refusal
    // lifted the same request signs.
    allowAppKeys = true;
    const again = await post('/authorize-sign', body);
    expect(again.status).toBe(200);
    expect(signed.length).toBe(1);
  });

  test('sign refuses key.delete', async () => {
    const { token, allowed } = await contextFor({ [urn('/secrets/x')]: ['tinycloud.encryption/key.delete'] });
    const preview = await post('/authorize-sign-preview', { authorizationContextToken: token, selectedActionIds: allowed });
    const { previewApprovalToken } = await preview.json() as { previewApprovalToken: string };
    allowAppKeys = false;
    const res = await post('/authorize-sign', { authorizationContextToken: token, previewApprovalToken, selectedActionIds: allowed, protocolVersion: 1 });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({ code: 'key_delete_not_grantable' });
    expect(signed).toEqual([]);
  });
});

describe('POST / (managed approval) for a context bound to an apps/ message', () => {
  test('answers 400 and signs nothing: the request is outside the default baseline', async () => {
    const siwe = siweWith(APPS_KEY);
    allowAppKeys = true;
    const prepared = await post('/authorize-sign-prepare', prepareBody(siwe));
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as {
      authorizationContextToken: string;
      allowedActionIds: string[];
    };
    allowAppKeys = false;
    const body = {
      keyId: keyRecord.id,
      jwk,
      host: 'https://node.tinycloud.xyz',
      prepared: { siwe },
      authorizationContextToken,
      selectedActionIds: allowedActionIds,
      protocolVersion: 1,
    };
    const res = await post('/', body);
    expect(res.status).toBe(400);
    expect(signed).toEqual([]);
  });
});

describe('POST /complete with a wallet-signed apps/ message', () => {
  test.each([
    ['an app key', APPS_KEY, 'app_key_grant_refused'],
    ['key.delete', { [urn('/secrets/x')]: ['tinycloud.encryption/key.delete'] }, 'key_delete_not_grantable'],
  ])('refuses %s', async (_name, raw, code) => {
    const siwe = siweWith(raw);
    const res = await post('/complete', {
      prepared: { siwe, spaceId: SPACE, chainId: 1 },
      signature: `0x${'11'.repeat(65)}`,
      host: 'https://node.tinycloud.xyz',
      jwk,
    });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({ code });
    expect(signed).toEqual([]);
  });
});

describe('permissions that name an apps/ key', () => {
  const permissions = [{ service: 'tinycloud.encryption', space: 'encryption', path: urn('/apps/xyz.tinycloud.listen/k'), actions: ['tinycloud.encryption/decrypt'] }];

  test.each(['/prepare', '/'])('%s answers 400 and signs nothing', async (path) => {
    const res = await post(path, { keyId: keyRecord.id, jwk, host: 'https://node.tinycloud.xyz', permissions });
    expect(res.status).toBe(400);
    expect(signed).toEqual([]);
  });
});

describe('POST /sign (session principal)', () => {
  function sign(message: string) {
    return post('/sign', { address, chainId: 1, message, type: 'siwe', keyId: keyRecord.id });
  }

  test('refuses an app key', async () => {
    const res = await sign(siweWith(APPS_KEY));
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual({ approved: false, code: 'app_key_grant_refused', reason: "App keys can only be requested through a website's sign-in, not from the command line or a device sign-in, so OpenKey didn't approve this request." });
    expect(signed).toEqual([]);
  });

  test('refuses key.delete', async () => {
    const res = await sign(siweWith({ [urn('/secrets/x')]: ['tinycloud.encryption/key.delete'] }));
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({ approved: false, code: 'key_delete_not_grantable' });
    expect(signed).toEqual([]);
  });
});
