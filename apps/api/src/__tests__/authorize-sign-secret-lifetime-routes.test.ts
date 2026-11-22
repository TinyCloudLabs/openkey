// TC-3800: in the frame (/authorize-sign-preview, /authorize-sign) a grant that may `decrypt` or `key.create` on a key
// or prefix under `default/secrets/` lasts 7 days at most, whatever the app asked or the owner picked: the preview
// brings a later expiry back to 7 days from now and those are the bytes signed. A whole network's `decrypt` is held
// the same way only while `OPENKEY_NETWORK_DECRYPT_CAP=enabled`.

import './tc1777-test-env';
import { afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { verifyMessage } from 'ethers';
import { mockModules, replaceModules } from './mock-module';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const ORIGIN = 'https://thirdparty.example';
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const HOST = 'https://node.tinycloud.xyz';
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';
const DAY_MS = 86_400_000;

let signed: string[] = [];
const unsealMock = mock(async () => privateKey);
const keyRecord = { id: 'key_1', userId: user.id, address, keyType: 'MANAGED', archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null };
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
    unseal: unsealMock,
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
  '../services/manifest-origin-fetch': () => ({ fetchAndBindWellKnownManifest: mock(async () => ({ ok: false, reason: 'not configured' })) }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

// Loaded after the module mocks above, under their own specifiers so no other test file's copies are reused.
beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?authorize-sign-secret-lifetime' as string
  ));
  // POST /sign as the owner's own browser session (the Auto-Sign path).
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?authorize-sign-secret-lifetime' as string
  ));
});

beforeEach(() => {
  signed = [];
  unsealMock.mockClear();
  resetContexts?.();
});
afterEach(() => {
  delete process.env.OPENKEY_NETWORK_DECRYPT_CAP;
});

function siweFor(rawAbilities: Record<string, string[]>, lifetimeMs: number): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: new URL(ORIGIN).host,
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + lifetimeMs).toISOString(),
    spaceId: SPACE,
    jwk,
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
    ...(Object.keys(rawAbilities).length > 0 ? { rawAbilities } : {}),
  }).siwe;
}

function post(path: string, body: unknown) {
  return router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
}

const expiryOf = (siwe: string) => Date.parse(/^Expiration Time: (.+)$/m.exec(siwe)?.[1] ?? '');
const elevatedIds = (allowed: string[]) =>
  allowed.filter((id) => id.includes('urn:tinycloud:encryption:') && /\0(tinycloud\.)?encryption\/(decrypt|key\.create)$/.test(id));

/** Prepare, preview (optionally with the owner's expiry) and sign; returns the signed bytes. */
async function approve(raw: Record<string, string[]>, lifetimeMs: number, opts: { expiryChangeable?: boolean; ownerPicks?: string } = {}) {
  const prepared = await post('/authorize-sign-prepare', {
    keyId: keyRecord.id, siwe: siweFor(raw, lifetimeMs), jwk, host: HOST, requestOrigin: ORIGIN, reportedOrigin: ORIGIN,
    ...(opts.expiryChangeable ? { expiryChangeable: true } : {}),
  });
  expect(prepared.status, await prepared.clone().text()).toBe(200);
  const { authorizationContextToken, allowedActionIds } = await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
  const preview = await post('/authorize-sign-preview', {
    authorizationContextToken,
    selectedActionIds: allowedActionIds,
    elevatedDecision: { allowed: elevatedIds(allowedActionIds) },
    ...(opts.ownerPicks === undefined ? {} : { expirationTime: opts.ownerPicks }),
  });
  expect(preview.status, await preview.clone().text()).toBe(200);
  const { previewApprovalToken, signedMessage: previewed } = await preview.json() as { previewApprovalToken: string; signedMessage: string };
  const res = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken, selectedActionIds: allowedActionIds, protocolVersion: 1 });
  expect(res.status, await res.clone().text()).toBe(200);
  const result = await res.json() as { signedMessage: string; signature: string };
  expect(result.signedMessage).toBe(previewed);
  expect(verifyMessage(result.signedMessage, result.signature)).toBe(address);
  return result.signedMessage;
}

/** The signed expiry is 7 days from the preview, within the test's own run. */
function expectSevenDays(bytes: string, before: number) {
  const expiry = expiryOf(bytes);
  expect(expiry).toBeGreaterThanOrEqual(before + 7 * DAY_MS - 1000);
  expect(expiry).toBeLessThanOrEqual(Date.now() + 7 * DAY_MS);
}

const SECRET_SHAPES: Array<[string, Record<string, string[]>]> = [
  ["decrypt on one secret's key", { [urn('/secrets/openai_api_key')]: [`${E}decrypt`] }],
  ['key.create on a scoped secret key', { [urn('/secrets/scoped/work/api_key')]: [`${E}key.create`] }],
  ['decrypt on every secret (secrets/)', { [urn('/secrets/')]: [`${E}decrypt`] }],
];

describe('the frame holds a grant on secret keys to 7 days', () => {
  test.each(SECRET_SHAPES)("%s: the app's 30 days are signed as 7, for an app that did not opt in to a changed expiry", async (_name, raw) => {
    const before = Date.now();
    expectSevenDays(await approve(raw, 30 * DAY_MS), before);
  });

  test.each(SECRET_SHAPES)("%s: the owner's 30 days are signed as 7", async (_name, raw) => {
    const before = Date.now();
    const ownerPicks = new Date(Date.now() + 30 * DAY_MS).toISOString();
    expectSevenDays(await approve(raw, DAY_MS, { expiryChangeable: true, ownerPicks }), before);
  });

  test("the owner's 2 days stay 2 days", async () => {
    const ownerPicks = new Date(Math.floor((Date.now() + 2 * DAY_MS) / 1000) * 1000).toISOString();
    const bytes = await approve(SECRET_SHAPES[0]![1], 30 * DAY_MS, { expiryChangeable: true, ownerPicks });
    expect(expiryOf(bytes)).toBe(Date.parse(ownerPicks));
  });

  test("the app's 3 days stay 3 days", async () => {
    const before = Date.now();
    const bytes = await approve(SECRET_SHAPES[0]![1], 3 * DAY_MS);
    expect(expiryOf(bytes)).toBeLessThan(before + 4 * DAY_MS);
  });

  test('a grant without secret keys keeps its 30 days', async () => {
    const before = Date.now();
    const bytes = await approve({ [urn('/qa/')]: [`${E}decrypt`] }, 30 * DAY_MS);
    expect(expiryOf(bytes)).toBeGreaterThan(before + 29 * DAY_MS);
  });
});

describe('a whole network decrypt follows OPENKEY_NETWORK_DECRYPT_CAP', () => {
  const network = { [urn('')]: [`${E}decrypt`] };

  test('off (the default): the 30 days are signed as asked', async () => {
    const before = Date.now();
    expect(expiryOf(await approve(network, 30 * DAY_MS))).toBeGreaterThan(before + 29 * DAY_MS);
  });

  test('enabled: the 30 days are signed as 7', async () => {
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    const before = Date.now();
    expectSevenDays(await approve(network, 30 * DAY_MS), before);
  });
});

const SECRET_REFUSED = {
  error: 'This request asks for secret access longer than 7 days. Secret access lasts at most 7 days, so ask again with an expiry of 7 days or less.',
  code: 'secret_lifetime_exceeded',
};
const NETWORK_REFUSED = {
  error: 'This request asks for access to secrets or encrypted data longer than 7 days. Access to secrets or encrypted data lasts at most 7 days, so ask again with an expiry of 7 days or less.',
  code: 'secret_lifetime_exceeded',
};

describe('/authorize-sign refuses a preview that outlives the cap', () => {
  test('a whole network decrypt previewed for 30 days, then the network cap turned on: refused, nothing signed', async () => {
    const prepared = await post('/authorize-sign-prepare', {
      keyId: keyRecord.id, siwe: siweFor({ [urn('')]: [`${E}decrypt`] }, 30 * DAY_MS), jwk, host: HOST, requestOrigin: ORIGIN, reportedOrigin: ORIGIN,
    });
    expect(prepared.status).toBe(200);
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
    const preview = await post('/authorize-sign-preview', {
      authorizationContextToken, selectedActionIds: allowedActionIds, elevatedDecision: { allowed: elevatedIds(allowedActionIds) },
    });
    expect(preview.status).toBe(200);
    const { previewApprovalToken } = await preview.json() as { previewApprovalToken: string };
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    const res = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken, selectedActionIds: allowedActionIds, protocolVersion: 1 });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(NETWORK_REFUSED);
    expect(signed).toEqual([]);
  });
});

describe('POST /sign (session principal, Auto-Sign) refuses signed bytes over 7 days', () => {
  const sign = (message: string) => post('/sign', { address, chainId: 1, message, type: 'siwe', keyId: keyRecord.id });

  test.each(SECRET_SHAPES)('%s for 30 days: refused, nothing signed', async (_name, raw) => {
    const res = await sign(siweFor(raw, 30 * DAY_MS));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ approved: false, code: SECRET_REFUSED.code, reason: SECRET_REFUSED.error });
    expect(signed).toEqual([]);
  });

  // Auto-Sign signs only bootstrap scopes; anything else that passes the 7-day guard goes on to the approval screen.
  test('a whole network decrypt for 30 days: sent on to approval with the network cap off, refused with it on in the wider words', async () => {
    const message = siweFor({ [urn('')]: [`${E}decrypt`] }, 30 * DAY_MS);
    const off = await sign(message);
    expect(off.status).toBe(200);
    expect(await off.json()).toMatchObject({ approved: false, needsApproval: true });
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    const on = await sign(message);
    expect(on.status).toBe(400);
    expect(await on.json()).toEqual({ approved: false, code: NETWORK_REFUSED.code, reason: NETWORK_REFUSED.error });
    expect(signed).toEqual([]);
  });

  test("one secret's key for 7 days passes the guard and is sent on to approval", async () => {
    const res = await sign(siweFor(SECRET_SHAPES[0]![1], 7 * DAY_MS - 60_000));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ approved: false, needsApproval: true });
  });
});

// Every shape OpenKey shows as all secrets: `secrets` itself, a prefix under it, or a path the node's key grammar
// refuses but that reads as one of them once lower-cased and percent-decoded. The frame takes each (and the page shows
// the all-secrets card); each is held to 7 days.
const ALL_SECRETS_SHAPES: Array<[string, Record<string, string[]>]> = [
  '/secrets', '/secrets/scoped/work/', '/secrets/scoped/', '/Secrets/', '/SECRETS/', '/SECRETS/x', '/Secrets/openai_api_key',
  '/secrets%2F', '/secrets%2f', '/secrets%2Fopenai_api_key', '/secrets%2fx',
].map((rest) => [`decrypt on default${rest}`, { [urn(rest)]: [`${E}decrypt`] }]);

describe('every shape of a grant on all secrets', () => {
  test.each(ALL_SECRETS_SHAPES)('%s: /authorize-sign-prepare offers it as a warned permission', async (_name, raw) => {
    const prepared = await post('/authorize-sign-prepare', {
      keyId: keyRecord.id, siwe: siweFor(raw, DAY_MS), jwk, host: HOST, requestOrigin: ORIGIN, reportedOrigin: ORIGIN,
    });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    const { allowedActionIds } = await prepared.json() as { allowedActionIds: string[] };
    expect(elevatedIds(allowedActionIds)).toEqual([expect.stringContaining(Object.keys(raw)[0]!)]);
  });

  test.each(ALL_SECRETS_SHAPES)("%s: the frame signs the app's 30 days as 7", async (_name, raw) => {
    const before = Date.now();
    expectSevenDays(await approve(raw, 30 * DAY_MS), before);
  });

  test.each(ALL_SECRETS_SHAPES)('%s: POST /sign refuses 30 days, nothing signed', async (_name, raw) => {
    const res = await post('/sign', { address, chainId: 1, message: siweFor(raw, 30 * DAY_MS), type: 'siwe', keyId: keyRecord.id });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ approved: false, code: SECRET_REFUSED.code, reason: SECRET_REFUSED.error });
    expect(signed).toEqual([]);
  });
});
