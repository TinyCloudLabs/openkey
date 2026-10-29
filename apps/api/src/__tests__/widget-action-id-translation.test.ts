// The signing windows' own action ids through prepare, preview and sign.
//
// The ids sent to /authorize-sign-preview and /authorize-sign here are the
// ones the popup and the embedded page send, both through
// `lib/widget-selection.ts`: the ids of the review model that
// capability-review builds from the message (`parseCapabilityReview`), for the
// selected actions. Nothing is written out by hand.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
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

/** The manifest fetched from the app's origin. */
function declaredManifest() {
  return { name: 'Listen', appId: APP_ID, prefix: APP_ID };
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

const DEFAULT_NETWORK = urn('');

/** The review model the signing window builds from the message. */
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

/** The ids the signing windows send: the default selection of the model through the shared helper. */
function windowIds(siwe: string): string[] {
  const model = reviewModel(siwe);
  return requestedActionIds(model, defaultSelection(model));
}

/** A message with only the raw encryption entries and no kv entry. */
function encryptionSiwe(raw: Record<string, string[]>): string {
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

type Preview = { signedMessage?: string; previewApprovalToken?: string; selectedActionKeys: string[]; code?: string; error?: string };

async function previewWith(siwe: string, ids: string[]) {
  const prepared = await post('/authorize-sign-prepare', prepareBody(siwe));
  expect(prepared.status).toBe(200);
  const { authorizationContextToken } = await prepared.json() as { authorizationContextToken: string };
  const preview = await post('/authorize-sign-preview', { authorizationContextToken, selectedActionIds: ids });
  return { authorizationContextToken, preview, previewBody: await preview.json() as Preview };
}

const SM_SHAPE = {
  [DEFAULT_NETWORK]: ['tinycloud.encryption/decrypt', 'tinycloud.encryption/network.create'],
};
const SECRETS_KEY = { [urn('/secrets/k')]: ['tinycloud.encryption/decrypt'] };
const KV_SIDE = { kv: { [SPACE]: ['tinycloud.kv/get', 'tinycloud.kv/put'] } };

describe('the ids both signing windows send for an encryption grant', () => {
  test.each([
    ['the default network decrypt', { [DEFAULT_NETWORK]: ['tinycloud.encryption/decrypt'] }],
    ['decrypt with network setup', SM_SHAPE],
    ['decrypt of one key', SECRETS_KEY],
  ] as Array<[string, Record<string, string[]>]>)('%s: prepare, preview, then sign with the ids of the selection the preview returned', async (_name, raw) => {
    const siwe = encryptionSiwe(raw);
    const model = reviewModel(siwe);
    const requested = windowIds(siwe);
    expect(requested.length).toBe(Object.values(raw).flat().length);

    const { authorizationContextToken, preview, previewBody } = await previewWith(siwe, requested);
    expect(preview.status).toBe(200);
    expect(previewBody.signedMessage).toBe(siwe);

    // What both pages do next: store the selection the preview describes, then build the sign ids from it.
    const reviewSelection = selectionFromPreview(previewBody, requested);
    expect([...reviewSelection].sort()).toEqual(model.permissions.flatMap((g) => g.actions.map((a) => a.id)).sort());
    const signIds = requestedActionIds(model, reviewSelection);
    expect([...signIds].sort()).toEqual([...requested].sort());

    const sign = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken, selectedActionIds: signIds, protocolVersion: 1 });
    expect(sign.status).toBe(200);
    expect(signed).toEqual([siwe]);
  });

  test('an encryption grant beside a kv grant', async () => {
    const now = new Date();
    const siwe = prepareSession({
      address, chainId: 1, domain: 'listen.tinycloud.xyz', issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 3_600_000).toISOString(), spaceId: SPACE, jwk,
      abilities: KV_SIDE as never, rawAbilities: { [DEFAULT_NETWORK]: ['tinycloud.encryption/decrypt'] },
    }).siwe;
    const requested = windowIds(siwe);
    expect(requested.length).toBe(3);
    const { preview, previewBody } = await previewWith(siwe, requested);
    expect(preview.status).toBe(200);
    expect(selectionFromPreview(previewBody, requested).size).toBe(3);
  });

  test('unticking the encryption grant keeps the rest signable', async () => {
    const now = new Date();
    const siwe = prepareSession({
      address, chainId: 1, domain: 'listen.tinycloud.xyz', issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 3_600_000).toISOString(), spaceId: SPACE, jwk,
      abilities: KV_SIDE as never, rawAbilities: { [DEFAULT_NETWORK]: ['tinycloud.encryption/decrypt'] },
    }).siwe;
    const model = reviewModel(siwe);
    const selection = new Set(defaultSelection(model));
    for (const grant of model.permissions) for (const action of grant.actions) if (action.ability.startsWith('tinycloud.encryption/')) selection.delete(action.id);
    const requested = requestedActionIds(model, selection);
    expect(requested.length).toBe(2);
    const { authorizationContextToken, preview, previewBody } = await previewWith(siwe, requested);
    expect(preview.status).toBe(200);
    expect(selectionFromPreview(previewBody, requested).size).toBe(2);
    const sign = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken, selectedActionIds: requested, protocolVersion: 1 });
    expect(sign.status).toBe(200);
  });

  test('a kv-only request is unchanged', async () => {
    const siwe = siweWith();
    const requested = windowIds(siwe);
    expect(requested.length).toBe(2);
    const { preview, previewBody } = await previewWith(siwe, requested);
    expect(preview.status).toBe(200);
    expect(selectionFromPreview(previewBody, requested).size).toBe(2);
  });
});
