// The approval view's own action ids through prepare, preview and sign.
//
// The ids sent to /authorize-sign-preview and /authorize-sign here are the
// ones the popup and the embedded page send, both through
// `lib/widget-selection.ts`: the ids of the review model that
// capability-review builds from the message (`parseCapabilityReview`), for the
// selected actions. Nothing is written out by hand.

import './tc1777-test-env';
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import { parseManifestKeys } from '../services/app-key-gate';
// The approval view's own code, loaded by path: it lives in the web app and the
// capability-review package, outside this project's source root.
const loadSource = (relative: string) => import(new URL(relative, import.meta.url).href);
type Selection = { permissions: Array<{ actions: Array<{ id: string; ability: string }> }> };
const { defaultSelection, parseCapabilityReview } = (await loadSource('../../../../packages/capability-review/src/index.ts')) as {
  defaultSelection: (model: Selection) => Set<string>;
  parseCapabilityReview: (input: unknown) => Selection;
};
const { requestedActionIds, selectionFromPreview } = (await loadSource('../../../web/src/lib/widget-selection.ts')) as {
  requestedActionIds: (model: Selection, selection: ReadonlySet<string>) => string[];
  selectionFromPreview: (preview: Record<string, unknown>, requested: readonly string[]) => Set<string>;
};

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
  ({ delegateRouter: router } = await import('../routes/delegate?app-key-widget-ids' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?app-key-widget-ids' as string
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
const MANIFEST_REFUSED = "OpenKey couldn't check this website's app details, so it didn't approve this request.";
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


/** The review model the approval view builds from the message. */
function reviewModel(siwe: string) {
  return parseCapabilityReview({
    message: siwe,
    signer: { label: 'Key', address, chainId: 1, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'listen.tinycloud.xyz',
      verifiedOrigin: ORIGIN,
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

/**
 * The ids the approval view sends: the page's own `defaultSelection` of the
 * model, minus the abilities `drop` names, through its own
 * `requestedActionIds`.
 */
function widgetIds(siwe: string, drop: (ability: string) => boolean = () => false): string[] {
  const model = reviewModel(siwe);
  const selection = new Set(defaultSelection(model));
  for (const grant of model.permissions) {
    for (const action of grant.actions) if (drop(action.ability)) selection.delete(action.id);
  }
  return requestedActionIds(model, selection);
}

/** What both signing pages do with a preview: the same validation, then the review selection it describes. */
function previewAgrees(preview: Record<string, unknown>, requested: string[]): boolean {
  try {
    return selectionFromPreview(preview, requested).size === requested.length;
  } catch {
    return false;
  }
}

/** A message with only the raw encryption entry: no kv entry, no network.create. */
function encryptionOnlySiwe(raw: Record<string, string[]>): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: 'listen.tinycloud.xyz',
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: SPACE,
    jwk,
    abilities: {} as never,
    rawAbilities: raw,
  }).siwe;
}

const NODE_SHAPE = { [PREFIX_URN]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] };

async function throughTheWidget(siwe: string, ids = widgetIds(siwe)) {
  const prepared = await post('/authorize-sign-prepare', prepareBody(siwe));
  expect(prepared.status).toBe(200);
  const { authorizationContextToken } = await prepared.json() as { authorizationContextToken: string };
  const preview = await post('/authorize-sign-preview', { authorizationContextToken, selectedActionIds: ids });
  const previewBody = await preview.json() as { signedMessage?: string; previewApprovalToken?: string; selectedActionKeys: string[]; permissions: Array<{ service: string; space: string; path: string; actions: string[] }>; code?: string; error?: string };
  return { authorizationContextToken, preview, previewBody, ids };
}

describe('the approval view\'s ids for app keys', () => {
  test('exactly the node\'s shape: key.create and decrypt on the prefix, nothing else', async () => {
    const siwe = encryptionOnlySiwe(NODE_SHAPE);
    const ids = widgetIds(siwe);
    expect(ids).toHaveLength(2);
    const { authorizationContextToken, preview, previewBody } = await throughTheWidget(siwe, ids);
    expect(preview.status).toBe(200);
    expect(previewBody.signedMessage).toBe(siwe);
    expect(previewAgrees(previewBody, ids)).toBe(true);

    const sign = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken, selectedActionIds: ids, protocolVersion: 1 });
    expect(sign.status).toBe(200);
    const signBody = await sign.json() as { signedMessage: string; selectedActionKeys: string[] };
    expect(signBody.signedMessage).toBe(siwe);
    expect(signed).toEqual([siwe]);
    expect(recapKeys(signBody.signedMessage)).toEqual([PREFIX_URN]);
  });

  test('the prefix with a kv sibling, every action selected', async () => {
    const siwe = siweWith(PREFIX);
    const { authorizationContextToken, preview, previewBody, ids } = await throughTheWidget(siwe);
    expect(ids).toHaveLength(4);
    expect(preview.status).toBe(200);
    expect(previewAgrees(previewBody, ids)).toBe(true);
    const sign = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken, selectedActionIds: ids, protocolVersion: 1 });
    expect(sign.status).toBe(200);
    expect(signed).toEqual([siwe]);
  });

  test('an exact key with a kv sibling', async () => {
    const siwe = siweWith(APPS_KEY);
    const { preview, previewBody, ids } = await throughTheWidget(siwe);
    expect(preview.status).toBe(200);
    expect(previewAgrees(previewBody, ids)).toBe(true);
  });

  test('the account\'s default network decrypt goes through the same path', async () => {
    const siwe = encryptionOnlySiwe({ [urn('')]: ['tinycloud.encryption/decrypt'] });
    const { preview, previewBody, ids } = await throughTheWidget(siwe);
    expect(ids).toHaveLength(1);
    expect(preview.status).toBe(200);
    expect(previewAgrees(previewBody, ids)).toBe(true);
  });

  test('removing the whole app-key group with the view\'s ids keeps the rest signable', async () => {
    const siwe = siweWith(PREFIX);
    const ids = widgetIds(siwe, (ability) => !ability.startsWith('tinycloud.kv/'));
    expect(ids).toHaveLength(2);
    const { authorizationContextToken, preview, previewBody } = await throughTheWidget(siwe, ids);
    expect(preview.status).toBe(200);
    expect(previewAgrees(previewBody, ids)).toBe(true);
    expect(recapKeys(previewBody.signedMessage!).some((key) => key.startsWith('urn:tinycloud:encryption'))).toBe(false);
    const sign = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken, selectedActionIds: ids, protocolVersion: 1 });
    expect(sign.status).toBe(200);
  });

  test('a selection that keeps an app-key id and drops another is the partial refusal', async () => {
    const siwe = siweWith(PREFIX);
    const ids = widgetIds(siwe, (ability) => ability.endsWith('key.create'));
    const { preview, previewBody } = await throughTheWidget(siwe, ids);
    expect(preview.status).toBe(400);
    expect(previewBody.code).toBe('app_key_group_partial');
  });
});

describe('the order both signing pages follow', () => {
  test('sign with the ids of the selection the preview returned', async () => {
    for (const raw of [PREFIX, APPS_KEY, { [urn('')]: ['tinycloud.encryption/decrypt'] }]) {
      const siwe = raw === PREFIX || raw === APPS_KEY ? siweWith(raw) : encryptionOnlySiwe(raw);
      const model = reviewModel(siwe);
      const requested = widgetIds(siwe);
      const { authorizationContextToken, preview, previewBody } = await throughTheWidget(siwe, requested);
      expect(preview.status).toBe(200);
      // The page stores the selection the preview describes, then builds the sign ids from it.
      const reviewSelection = selectionFromPreview(previewBody, requested);
      expect([...reviewSelection].sort()).toEqual(model.permissions.flatMap((g) => g.actions.map((a) => a.id)).sort());
      const signIds = requestedActionIds(model, reviewSelection);
      expect([...signIds].sort()).toEqual([...requested].sort());
      const sign = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken, selectedActionIds: signIds, protocolVersion: 1 });
      expect(sign.status).toBe(200);
    }
  });
});

describe('the owner and the prefix as the node and OpenKey spell them', () => {
  test('a lower-case address in the owner is refused as not the account\'s, never normalised', async () => {
    const lower = { [PREFIX_URN.replace(address, address.toLowerCase())]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] };
    const { res, body } = await prepare(encryptionOnlySiwe(lower));
    expect(res.status).toBe(403);
    expect(body).toEqual({ error: "This request doesn't match your account, so OpenKey didn't approve it.", code: 'app_key_grant_refused' });
    expect(signed).toEqual([]);
  });

  test('a bare address in place of the did:pkh owner is refused', async () => {
    const bare = { [`urn:tinycloud:encryption:${address}:default/apps/${APP_ID}/`]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] };
    const { res, body } = await prepare(encryptionOnlySiwe(bare));
    expect(res.status).toBe(403);
    expect(body.code).toBe('app_key_grant_refused');
  });

  test('the prefix without its trailing slash is refused, the prefix with one extra is refused', async () => {
    for (const resource of [PREFIX_URN.slice(0, -1), `${PREFIX_URN}/`]) {
      const { res } = await prepare(encryptionOnlySiwe({ [resource]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] }));
      expect(res.status).toBe(403);
    }
  });

  test('declared key.create and decrypt on the prefix covers that request and no more', async () => {
    const { res } = await prepare(encryptionOnlySiwe(NODE_SHAPE));
    expect(res.status).toBe(200);
    const extra = { [PREFIX_URN]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt', 'tinycloud.encryption/key.block'] };
    const refusal = await prepare(encryptionOnlySiwe(extra));
    expect(refusal.res.status).toBe(403);
  });
});

describe('key.block and key.unblock are admitted only on the requesting app\'s own keys', () => {
  const A_ORIGIN = 'https://a.example';
  const A_ID = 'example.a';
  const B_ID = 'example.b';
  const BLOCK = ['tinycloud.encryption/key.block'];
  const UNBLOCK = ['tinycloud.encryption/key.unblock'];

  function siweAt(domain: string, raw: Record<string, string[]>): string {
    const now = new Date();
    return prepareSession({
      address,
      chainId: 1,
      domain,
      issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
      spaceId: SPACE,
      jwk,
      abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
      rawAbilities: raw,
    }).siwe;
  }

  /** Site `https://a.example` whose manifest names `appId` and lists `keys`. */
  async function fromA(raw: Record<string, string[]>, keys: unknown, appId: string = A_ID) {
    manifestBindResult = { ok: true, fetchedDigest: 'a'.repeat(64), manifest: declaredManifest(keys, appId) };
    return prepare(siweAt('a.example', raw), { requestOrigin: A_ORIGIN, reportedOrigin: A_ORIGIN });
  }

  const ownBlock = [{ prefix: `apps/${A_ID}/`, abilities: ['key.block', 'key.unblock'] }];

  test('block and unblock on its own prefix, when the manifest lists them', async () => {
    for (const ability of [BLOCK, UNBLOCK]) {
      const { res } = await fromA({ [urn(`/apps/${A_ID}/`)]: ability }, ownBlock);
      expect(res.status).toBe(200);
    }
    const key = await fromA({ [urn(`/apps/${A_ID}/k`)]: BLOCK }, ownBlock);
    expect(key.res.status).toBe(200);
  });

  test('block on its own prefix is refused when the manifest does not list it', async () => {
    const { res, body } = await fromA({ [urn(`/apps/${A_ID}/`)]: BLOCK }, [{ prefix: `apps/${A_ID}/`, abilities: ['decrypt'] }]);
    expect(res.status).toBe(403);
    expect(body.error).toBe(NOT_DECLARED);
  });

  test('another app\'s prefix or key is refused, whatever the manifest lists', async () => {
    for (const ability of [BLOCK, UNBLOCK]) {
      for (const resource of [urn(`/apps/${B_ID}/`), urn(`/apps/${B_ID}/k`)]) {
        const { res, body } = await fromA({ [resource]: ability }, ownBlock);
        expect(res.status).toBe(403);
        expect(body.error).toBe(NOT_DECLARED);
      }
    }
  });

  test('a manifest that names the other app on this site is refused as an app id this site does not hold', async () => {
    const { res, body } = await fromA({ [urn(`/apps/${B_ID}/`)]: BLOCK }, [{ prefix: `apps/${B_ID}/`, abilities: ['key.block'] }], B_ID);
    expect(res.status).toBe(403);
    expect(body.error).toBe(APP_ID_REFUSED);
  });

  test('an id that extends its own id is another app\'s prefix and is refused', async () => {
    const { res, body } = await fromA({ [urn(`/apps/${A_ID}.sub/`)]: BLOCK }, ownBlock);
    expect(res.status).toBe(403);
    expect(body.error).toBe(NOT_DECLARED);
  });

  test('block or unblock on a prefix that is not under apps/ is refused', async () => {
    for (const ability of [BLOCK, UNBLOCK]) {
      for (const resource of [urn('/secrets/'), urn('/secrets/k'), urn('/'), urn('')]) {
        const { res, body } = await fromA({ [resource]: ability }, ownBlock);
        expect(res.status).toBe(403);
        expect(body.code).toBe('app_key_grant_refused');
      }
    }
  });

  test('block on a key outside apps/ is refused beside an app key that is listed, and the whole request is refused', async () => {
    const { res, body } = await fromA({ [urn(`/apps/${A_ID}/`)]: BLOCK, [urn('/secrets/')]: BLOCK }, ownBlock);
    expect(res.status).toBe(403);
    expect(body.code).toBe('app_key_grant_refused');
    expect(signed).toEqual([]);
  });

  test('create and decrypt outside apps/ are not part of this refusal', async () => {
    const { res } = await fromA({ [urn('/secrets/')]: ['tinycloud.encryption/decrypt'] }, ownBlock);
    expect(res.status).toBe(200);
  });
});
