// Route-level checks for the admission of `apps/` key grants at
// /authorize-sign-prepare and for what /authorize-sign-preview and
// /authorize-sign do with an admitted context.

import './tc1777-test-env';
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import { parseManifestKeys } from '../services/app-key-gate';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const ORIGIN = 'https://listen.tinycloud.xyz';
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;

const APP_ID = 'xyz.tinycloud.listen';

/** The manifest fetched from the app's origin: the prefix declared with create and decrypt. */
function declaredManifest(keys: unknown = [{ prefix: `apps/${APP_ID}/`, abilities: ['key.create', 'decrypt'] }], appId: string = APP_ID) {
  return {
    name: 'Listen',
    appId,
    prefix: appId,
    declaredAppId: appId,
    declaredKeys: parseManifestKeys(appId, keys),
  };
}

let signed: string[] = [];
let manifestBindResult: { ok: boolean; manifest?: Record<string, unknown>; fetchedDigest?: string; reason?: string } = {
  ok: true,
  fetchedDigest: 'a'.repeat(64),
  manifest: declaredManifest(),
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
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];

beforeAll(async () => {
  ({ delegateRouter: router } = await import('../routes/delegate?app-key-admission-routes' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?app-key-admission-routes' as string
  ));
});

beforeEach(() => {
  signed = [];
  manifestBindResult = {
    ok: true,
    fetchedDigest: 'a'.repeat(64),
    manifest: declaredManifest(),
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
const ORIGIN_REFUSED = "App keys can only be requested by the app's own website, so OpenKey didn't approve this request.";
const APP_ID_REFUSED = "This app doesn't belong to this website, so OpenKey didn't approve its keys.";
const KEYS_REFUSED = "This website's list of app keys can't be read, so OpenKey didn't approve this request.";
const ACCOUNT_REFUSED = "This request doesn't match your account, so OpenKey didn't approve it.";
const PARTIAL_REFUSED = "App keys can only be approved together, so OpenKey didn't approve this request.";

const PREFIX_URN = urn(`/apps/${APP_ID}/`);
const PREFIX = { [PREFIX_URN]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] };

async function prepare(siwe: string, over: Record<string, unknown> = {}) {
  const res = await post('/authorize-sign-prepare', { ...prepareBody(siwe), ...over });
  const body = await res.json() as { authorizationContextToken?: string; allowedActionIds?: string[]; metadataTrust?: { status: string }; error?: string; code?: string };
  return { res, body };
}

function recapKeys(message: string): string[] {
  const token = /urn:recap:(\S+)/.exec(message)?.[1] ?? '';
  return Object.keys((JSON.parse(Buffer.from(token, 'base64url').toString('utf8')) as { att: Record<string, unknown> }).att);
}

describe('an admitted prefix next to a kv sibling', () => {
  test('select all: prepare, preview and sign sign the request bytes unchanged, once', async () => {
    const siwe = siweWith(PREFIX);
    const { res, body } = await prepare(siwe);
    expect(res.status).toBe(200);
    expect(body.metadataTrust?.status).toBe('origin-bound');
    const selected = body.allowedActionIds!;
    expect(selected).toHaveLength(4);

    const preview = await post('/authorize-sign-preview', { authorizationContextToken: body.authorizationContextToken, selectedActionIds: selected });
    expect(preview.status).toBe(200);
    const previewBody = await preview.json() as { signedMessage: string; previewApprovalToken: string };
    expect(previewBody.signedMessage).toBe(siwe);
    expect(recapKeys(previewBody.signedMessage)).toContain(PREFIX_URN);
    expect(PREFIX_URN.endsWith('/')).toBe(true);

    const request = { authorizationContextToken: body.authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken, selectedActionIds: selected, protocolVersion: 1 };
    const sign = await post('/authorize-sign', request);
    expect(sign.status).toBe(200);
    const signBody = await sign.json() as { signedMessage: string };
    expect(signBody.signedMessage).toBe(siwe);
    expect(signed).toEqual([siwe]);

    const again = await post('/authorize-sign', request);
    expect(again.status).toBe(400);
    expect(signed).toHaveLength(1);
  });

  test('an exact key under the declared prefix is admitted too', async () => {
    const { res } = await prepare(siweWith(APPS_KEY));
    expect(res.status).toBe(200);
  });

  test('the owner removes the whole app-key group and keeps the rest: preview and sign succeed without the keys', async () => {
    const { body } = await prepare(siweWith(PREFIX));
    const kvOnly = body.allowedActionIds!.filter((id) => id.includes('tinycloud.kv'));
    expect(kvOnly).toHaveLength(2);
    const preview = await post('/authorize-sign-preview', { authorizationContextToken: body.authorizationContextToken, selectedActionIds: kvOnly });
    expect(preview.status).toBe(200);
    const previewBody = await preview.json() as { signedMessage: string; previewApprovalToken: string };
    expect(recapKeys(previewBody.signedMessage).some((key) => key.includes('urn:tinycloud:encryption'))).toBe(false);
    const sign = await post('/authorize-sign', { authorizationContextToken: body.authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken, selectedActionIds: kvOnly, protocolVersion: 1 });
    expect(sign.status).toBe(200);
    expect(signed).toHaveLength(1);
  });
});

describe('all or nothing: a selection that keeps an app-key row and drops anything else', () => {
  const dropKv = (id: string) => !id.includes('tinycloud.kv');
  const dropCreate = (id: string) => !id.includes('key.create');
  const dropOneKv = (id: string) => !id.includes('tinycloud.kv\u0000') || !id.endsWith('tinycloud.kv/put');

  test.each([
    ['the kv sibling is dropped', dropKv],
    ['one prefix ability is dropped', dropCreate],
    ['one kv action is dropped', dropOneKv],
  ])('%s: preview and sign answer 400 app_key_group_partial and sign nothing', async (_name, keep) => {
    const { body } = await prepare(siweWith(PREFIX));
    const selected = body.allowedActionIds!.filter(keep);
    expect(selected.length).toBeGreaterThan(0);
    expect(selected.length).toBeLessThan(4);
    const preview = await post('/authorize-sign-preview', { authorizationContextToken: body.authorizationContextToken, selectedActionIds: selected });
    expect(preview.status).toBe(400);
    expect(await preview.json()).toEqual({ error: PARTIAL_REFUSED, code: 'app_key_group_partial' });
    const sign = await post('/authorize-sign', { authorizationContextToken: body.authorizationContextToken, previewApprovalToken: 'okp_none', selectedActionIds: selected, protocolVersion: 1 });
    expect(sign.status).toBe(400);
    expect(await sign.json()).toMatchObject({ code: 'app_key_group_partial' });
    expect(signed).toEqual([]);
  });

  test('an empty selection is not a partial one', async () => {
    const { body } = await prepare(siweWith(PREFIX));
    const preview = await post('/authorize-sign-preview', { authorizationContextToken: body.authorizationContextToken, selectedActionIds: [] });
    expect(await preview.json()).not.toMatchObject({ code: 'app_key_group_partial' });
  });
});

describe('admission refusals at /authorize-sign-prepare', () => {
  async function refused(siwe: string, over: Record<string, unknown> = {}, expectedText = NOT_DECLARED) {
    const { res, body } = await prepare(siwe, over);
    expect(res.status).toBe(403);
    expect(body).toEqual({ error: expectedText, code: 'app_key_grant_refused' });
    expect(body.authorizationContextToken).toBeUndefined();
    expect(signed).toEqual([]);
  }

  test('an app id that does not belong to the origin host (string 13)', async () => {
    manifestBindResult = { ok: true, fetchedDigest: 'a'.repeat(64), manifest: declaredManifest(undefined, 'com.example.other') };
    await refused(siweWith({ [urn('/apps/com.example.other/')]: ['tinycloud.encryption/decrypt'] }), {}, APP_ID_REFUSED);
  });

  test('request and reported origins that differ (string 12)', async () => {
    await refused(siweWith(PREFIX), { reportedOrigin: 'https://notes.tinycloud.xyz' }, ORIGIN_REFUSED);
  });

  test('an upper-case origin is not folded (string 12)', async () => {
    await refused(siweWith(PREFIX), { requestOrigin: 'https://LISTEN.tinycloud.xyz', reportedOrigin: 'https://LISTEN.tinycloud.xyz' }, ORIGIN_REFUSED);
  });

  test('the plain browser flow does not require a reported-origin manifest-fetch hint', async () => {
    const { res, body } = await prepare(siweWith(PREFIX), {
      reportedOrigin: undefined,
      presentation: { displayName: 'Listen' },
    });
    expect(res.status).toBe(200);
    expect(body.metadataTrust?.status).toBe('unsigned');
    expect(body.allowedActionIds).toHaveLength(4);
  });

  test.each([
    ['an ability the manifest does not declare', { [PREFIX_URN]: ['tinycloud.encryption/key.block'] }],
    ['a deeper prefix', { [urn(`/apps/${APP_ID}/sub/`)]: ['tinycloud.encryption/decrypt'] }],
    ['another app prefix', { [urn('/apps/xyz.tinycloud.notes/')]: ['tinycloud.encryption/decrypt'] }],
  ])('%s (string 14)', async (_name, raw) => {
    await refused(siweWith(raw));
  });

  test.each([
    ['another owner', { [urn(`/apps/${APP_ID}/`).replace(address, '0x0000000000000000000000000000000000000001')]: ['tinycloud.encryption/decrypt'] }],
    ['another network', { [`urn:tinycloud:encryption:did:pkh:eip155:1:${address}:team/apps/${APP_ID}/`]: ['tinycloud.encryption/decrypt'] }],
  ])('%s: the request does not match the account (W3c)', async (_name, raw) => {
    await refused(siweWith(raw), {}, ACCOUNT_REFUSED);
  });

  test('an unfetchable manifest leaves app-key grants available with unsigned metadata', async () => {
    manifestBindResult = { ok: false, reason: 'digest mismatch' };
    const { res, body } = await prepare(siweWith(PREFIX));
    expect(res.status).toBe(200);
    expect(body.metadataTrust?.status).toBe('unsigned');
    expect(body.allowedActionIds).toHaveLength(4);
  });

  test('no manifest digest: app-key grants are admitted without fetching a manifest', async () => {
    const { res, body } = await prepare(siweWith(PREFIX), { presentation: { displayName: 'Listen' } });
    expect(res.status).toBe(200);
    expect(body.metadataTrust?.status).toBe('unsigned');
    expect(fetchAndBindWellKnownManifest).not.toHaveBeenCalled();
    expect(body.allowedActionIds).toHaveLength(4);
  });

  test('unsigned app-key admission completes prepare, preview, and explicit sign', async () => {
    const siwe = siweWith(PREFIX);
    const { res, body } = await prepare(siwe, {
      presentation: { displayName: 'Listen' },
      reportedOrigin: undefined,
    });
    expect(res.status).toBe(200);
    expect(body.metadataTrust?.status).toBe('unsigned');
    expect(fetchAndBindWellKnownManifest).not.toHaveBeenCalled();

    const preview = await post('/authorize-sign-preview', {
      authorizationContextToken: body.authorizationContextToken,
      selectedActionIds: body.allowedActionIds,
    });
    expect(preview.status).toBe(200);
    const previewBody = await preview.json() as { signedMessage: string; previewApprovalToken: string };
    expect(previewBody.signedMessage).toBe(siwe);

    const sign = await post('/authorize-sign', {
      authorizationContextToken: body.authorizationContextToken,
      previewApprovalToken: previewBody.previewApprovalToken,
      selectedActionIds: body.allowedActionIds,
      protocolVersion: 1,
    });
    expect(sign.status).toBe(200);
    expect(await sign.json()).toMatchObject({ signedMessage: siwe });
    expect(signed).toEqual([siwe]);
  });

  test.each([
    ['no keys block', undefined],
    ['an empty keys block', []],
  ])('%s: the key is not in the site\'s list (string 14)', async (_name, keys) => {
    manifestBindResult = {
      ok: true,
      fetchedDigest: 'a'.repeat(64),
      manifest: keys === undefined ? { name: 'Listen', appId: APP_ID, declaredAppId: APP_ID } : declaredManifest(keys),
    };
    await refused(siweWith(PREFIX));
  });

  test.each([
    ['a keys block that declares key.delete', [{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt', 'key.delete'] }]],
    ['a keys block with a second prefix', [{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt'] }, { prefix: `apps/${APP_ID}/`, abilities: ['key.create'] }]],
    ['a keys block that is not an array', 'apps/x'],
  ])('%s: the list cannot be read (W3d)', async (_name, keys) => {
    manifestBindResult = { ok: true, fetchedDigest: 'a'.repeat(64), manifest: declaredManifest(keys) };
    await refused(siweWith(PREFIX), {}, KEYS_REFUSED);
  });

  test('the manifest has only a camelCase appId: the site does not list the key (string 14)', async () => {
    manifestBindResult = { ok: true, fetchedDigest: 'a'.repeat(64), manifest: { name: 'Listen', appId: APP_ID, declaredKeys: parseManifestKeys(APP_ID, [{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt'] }]) } };
    await refused(siweWith(PREFIX));
  });

  test('key.delete beside a declared prefix is refused with its own text', async () => {
    const { res, body } = await prepare(siweWith({ ...PREFIX, [urn('/secrets/x')]: ['tinycloud.encryption/key.delete'] }));
    expect(res.status).toBe(403);
    expect(body.code).toBe('key_delete_not_grantable');
  });

  test('a SIWE header with a scheme is refused by the existing origin check', async () => {
    const siwe = siweWith(PREFIX).replace('listen.tinycloud.xyz wants you', 'https://listen.tinycloud.xyz wants you');
    const { res, body } = await prepare(siwe);
    expect(res.status).toBe(403);
    expect(body.code).toBe('siwe_origin_refused');
  });

  test('a SIWE without Expiration Time never reaches admission', async () => {
    const siwe = siweWith(PREFIX).replace(/^Expiration Time:.*\n/m, '');
    const { res, body } = await prepare(siwe);
    expect(res.status).toBe(400);
    expect(body.code).toBe('invalid_siwe_header');
  });

  test('an ordinary request with a declared manifest and no app keys is unchanged', async () => {
    const { res, body } = await prepare(siweWith());
    expect(res.status).toBe(200);
    expect(body.metadataTrust?.status).toBe('origin-bound');
  });
});

describe('plain app-key grants (no digest-matched manifest)', () => {
  const plain = { presentation: { displayName: 'Listen' }, reportedOrigin: undefined };
  const ALL_FOUR = ['key.create', 'decrypt', 'key.block', 'key.unblock'].map((a) => `tinycloud.encryption/${a}`);

  test('the origin prefix is admitted with all four abilities and never fetches a manifest', async () => {
    const { res, body } = await prepare(siweWith({ [PREFIX_URN]: ALL_FOUR }), plain);
    expect(res.status).toBe(200);
    expect(body.metadataTrust?.status).toBe('unsigned');
    expect(fetchAndBindWellKnownManifest).not.toHaveBeenCalled();
    for (const ability of ALL_FOUR) expect(body.allowedActionIds!.some((id) => id.endsWith(ability))).toBe(true);
  });

  test('an exact key under the origin prefix is admitted', async () => {
    const { res, body } = await prepare(siweWith(APPS_KEY), plain);
    expect(res.status).toBe(200);
    expect(body.allowedActionIds!.some((id) => id.includes('/apps/xyz.tinycloud.listen/k') && id.endsWith('decrypt'))).toBe(true);
  });

  test('one resource outside the origin prefix refuses the whole request', async () => {
    const mixed = { ...PREFIX, [urn('/apps/xyz.tinycloud.notes/')]: ['tinycloud.encryption/decrypt'] };
    const { res, body } = await prepare(siweWith(mixed), plain);
    expect(res.status).toBe(403);
    expect(body.code).toBe('app_key_grant_refused');
    expect(body.authorizationContextToken).toBeUndefined();
  });

  test.each([
    ['a sibling host\'s app prefix', { [urn('/apps/xyz.tinycloud.notes/')]: ['tinycloud.encryption/decrypt'] }],
    ['the shorter parent prefix', { [urn('/apps/xyz.tinycloud/')]: ['tinycloud.encryption/decrypt'] }],
  ])('%s is refused', async (_name, raw) => {
    const { res, body } = await prepare(siweWith(raw), plain);
    expect(res.status).toBe(403);
    expect(body.code).toBe('app_key_grant_refused');
    expect(signed).toEqual([]);
  });

  test('key.delete is refused', async () => {
    const { res, body } = await prepare(siweWith({ [PREFIX_URN]: ['tinycloud.encryption/key.delete'] }), plain);
    expect(res.status).toBe(403);
    expect(body.code).toBe('key_delete_not_grantable');
  });

  test('another owner is refused', async () => {
    const other = { [urn(`/apps/${APP_ID}/`).replace(address, '0x0000000000000000000000000000000000000001')]: ['tinycloud.encryption/decrypt'] };
    const { res, body } = await prepare(siweWith(other), plain);
    expect(res.status).toBe(403);
    expect(body.code).toBe('app_key_grant_refused');
  });

  test('an origin that cannot name an app is refused', async () => {
    const origin = 'https://listen.tinycloud.xyz:8443';
    const { res } = await prepare(siweWith(PREFIX), { ...plain, requestOrigin: origin });
    expect(res.status).toBe(403);
    expect(signed).toEqual([]);
  });

  test('a reported origin that differs from the browser origin is refused', async () => {
    const { res, body } = await prepare(siweWith(PREFIX), { presentation: { displayName: 'Listen' }, reportedOrigin: 'https://notes.tinycloud.xyz' });
    expect(res.status).toBe(403);
    expect(body.code).toBe('app_key_grant_refused');
  });

  test('a manifest that binds still narrows the request', async () => {
    manifestBindResult = { ok: true, fetchedDigest: 'a'.repeat(64), manifest: declaredManifest([{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt'] }]) };
    const { res, body } = await prepare(siweWith({ [PREFIX_URN]: ['tinycloud.encryption/key.block'] }));
    expect(res.status).toBe(403);
    expect(body.code).toBe('app_key_grant_refused');
  });
});

describe('a context that was not admitted for app keys', () => {
  test('a context issued for a request with no app keys cannot carry one at preview', async () => {
    const { body } = await prepare(siweWith());
    const preview = await post('/authorize-sign-preview', { authorizationContextToken: body.authorizationContextToken, selectedActionIds: body.allowedActionIds });
    expect(preview.status).toBe(200);
  });
});
