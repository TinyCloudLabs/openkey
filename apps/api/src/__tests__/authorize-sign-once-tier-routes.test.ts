// A sign-in whose grants reach all secrets or all encrypted data (the one-hour tier, `grantIsBroadOnce`) is
// expiry-changeable whatever the app sends, and an approval with no owner pick starts at one hour: the preview
// writes the hour into the bytes, those are the bytes signed, and the owner may choose longer up to the 7-day cap.
// Grants outside the tier keep the app's own time and the `expiry_not_changeable` refusal.

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
const HOUR_MS = 3_600_000;

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

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?authorize-sign-once-tier' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?authorize-sign-once-tier' as string
  ));
});

beforeEach(() => {
  signed = [];
  unsealMock.mockClear();
  resetContexts?.();
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
    abilities: {} as never,
    ...(Object.keys(rawAbilities).length > 0 ? { rawAbilities } : {}),
  }).siwe;
}

function post(path: string, body: unknown) {
  return router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
}

const expiryOf = (siwe: string) => Date.parse(/^Expiration Time: (.+)$/m.exec(siwe)?.[1] ?? '');
const elevatedIds = (allowed: string[]) =>
  allowed.filter((id) => id.includes('urn:tinycloud:encryption:') && /\0(tinycloud\.)?encryption\/(decrypt|key\.create)$/.test(id));

async function prepare(raw: Record<string, string[]>, lifetimeMs: number, opts: { expiryChangeable?: boolean } = {}) {
  const prepared = await post('/authorize-sign-prepare', {
    keyId: keyRecord.id, siwe: siweFor(raw, lifetimeMs), jwk, host: HOST, requestOrigin: ORIGIN, reportedOrigin: ORIGIN,
    ...(opts.expiryChangeable ? { expiryChangeable: true } : {}),
  });
  expect(prepared.status, await prepared.clone().text()).toBe(200);
  return await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
}

async function preview(prepared: { authorizationContextToken: string; allowedActionIds: string[] }, ownerPicks?: string, selectedActionIds?: string[]) {
  const res = await post('/authorize-sign-preview', {
    authorizationContextToken: prepared.authorizationContextToken,
    selectedActionIds: selectedActionIds ?? prepared.allowedActionIds,
    elevatedDecision: { allowed: elevatedIds(prepared.allowedActionIds) },
    ...(ownerPicks === undefined ? {} : { expirationTime: ownerPicks }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** Prepare, preview and sign; returns the signed bytes. */
async function approve(raw: Record<string, string[]>, lifetimeMs: number, opts: { expiryChangeable?: boolean; ownerPicks?: string } = {}) {
  const prepared = await prepare(raw, lifetimeMs, opts);
  const shown = await preview(prepared, opts.ownerPicks);
  expect(shown.status, JSON.stringify(shown.body)).toBe(200);
  const res = await post('/authorize-sign', {
    authorizationContextToken: prepared.authorizationContextToken,
    previewApprovalToken: shown.body.previewApprovalToken,
    selectedActionIds: prepared.allowedActionIds,
    protocolVersion: 1,
  });
  expect(res.status, await res.clone().text()).toBe(200);
  const result = await res.json() as { signedMessage: string; signature: string };
  expect(result.signedMessage).toBe(shown.body.signedMessage);
  expect(verifyMessage(result.signedMessage, result.signature)).toBe(address);
  return result.signedMessage;
}

function expectAboutOneHour(bytes: string, before: number) {
  const expiry = expiryOf(bytes);
  expect(expiry).toBeGreaterThan(before);
  expect(expiry).toBeLessThanOrEqual(Date.now() + HOUR_MS);
}

const PREFIX_DECRYPT = { [urn('/secrets/')]: [`${E}decrypt`] };
const NETWORK_DECRYPT = { [urn('')]: [`${E}decrypt`] };
const ONE_SECRET = { [urn('/secrets/openai_api_key')]: [`${E}decrypt`] };
const NOTES_KV = { [`${SPACE}/kv/notes/`]: ['tinycloud.kv/get'] };

describe('the one-hour tier defaults to one hour without an app opt-in', () => {
  test.each([
    ['decrypt on the secrets/ prefix', PREFIX_DECRYPT],
    ['decrypt on the whole network', NETWORK_DECRYPT],
  ])('%s: the app\'s 7 days are signed as one hour', async (_name, raw) => {
    const before = Date.now();
    expectAboutOneHour(await approve(raw, 7 * DAY_MS), before);
  });

  test.each([
    ['decrypt on the secrets/ prefix', PREFIX_DECRYPT],
    ['decrypt on the whole network', NETWORK_DECRYPT],
  ])('%s: the owner chooses up to the 7-day cap without an app opt-in', async (_name, raw) => {
    const picked = new Date(Math.floor((Date.now() + 7 * DAY_MS) / 1000) * 1000).toISOString();
    expect(expiryOf(await approve(raw, 7 * DAY_MS, { ownerPicks: picked }))).toBe(Date.parse(picked));
  });

  test('an owner pick past the 7-day cap is signed as 7 days', async () => {
    const before = Date.now();
    const picked = new Date(Date.now() + 30 * DAY_MS).toISOString();
    const expiry = expiryOf(await approve(PREFIX_DECRYPT, 7 * DAY_MS, { ownerPicks: picked }));
    expect(expiry).toBeGreaterThan(before + 7 * DAY_MS - 60_000);
    expect(expiry).toBeLessThanOrEqual(Date.now() + 7 * DAY_MS);
  });

  test('an app that asked for less than an hour keeps its own time', async () => {
    const before = Date.now();
    const expiry = expiryOf(await approve(PREFIX_DECRYPT, 30 * 60_000));
    expect(expiry).toBeLessThanOrEqual(before + HOUR_MS);
    expect(expiry).toBeLessThanOrEqual(before + 30 * 60_000 + 1000);
  });

  test('a broad selection reduced to an ordinary one signs the app\'s own time', async () => {
    const prepared = await prepare({ ...PREFIX_DECRYPT, ...NOTES_KV }, 7 * DAY_MS);
    const kvOnly = prepared.allowedActionIds.filter((id) => !id.includes('urn:tinycloud:encryption:'));
    expect(kvOnly.length).toBeGreaterThan(0);
    const shown = await preview(prepared, undefined, kvOnly);
    expect(shown.status, JSON.stringify(shown.body)).toBe(200);
    expect(expiryOf(shown.body.signedMessage)).toBeGreaterThan(Date.now() + 6 * DAY_MS);
  });
});

describe('the tier reads the app opt-in the same way', () => {
  test('expiryChangeable: true with a pick of 7 days signs 7 days', async () => {
    const picked = new Date(Math.floor((Date.now() + 7 * DAY_MS) / 1000) * 1000).toISOString();
    expect(expiryOf(await approve(PREFIX_DECRYPT, 7 * DAY_MS, { expiryChangeable: true, ownerPicks: picked }))).toBe(Date.parse(picked));
  });

  test('a pick of 30 days with the opt-in is signed as 7 days', async () => {
    const before = Date.now();
    const picked = new Date(Date.now() + 30 * DAY_MS).toISOString();
    const expiry = expiryOf(await approve(PREFIX_DECRYPT, 7 * DAY_MS, { expiryChangeable: true, ownerPicks: picked }));
    expect(expiry).toBeGreaterThan(before + 7 * DAY_MS - 60_000);
    expect(expiry).toBeLessThanOrEqual(Date.now() + 7 * DAY_MS);
  });
});

describe('grants outside the tier are unchanged', () => {
  test('decrypt on one named secret signs the app\'s time, and an owner pick without the opt-in is refused', async () => {
    const before = Date.now();
    const expiry = expiryOf(await approve(ONE_SECRET, 3 * DAY_MS));
    expect(expiry).toBeGreaterThan(before + 3 * DAY_MS - 60_000);
    expect(expiry).toBeLessThanOrEqual(Date.now() + 3 * DAY_MS);
    const prepared = await prepare(ONE_SECRET, 3 * DAY_MS);
    const refused = await preview(prepared, new Date(Date.now() + DAY_MS).toISOString());
    expect(refused.status).toBe(400);
    expect(refused.body.code).toBe('expiry_not_changeable');
  });

  test('a KV-only request keeps the app\'s time and the same refusal', async () => {
    const prepared = await prepare(NOTES_KV, 7 * DAY_MS);
    const refused = await preview(prepared, new Date(Date.now() + DAY_MS).toISOString());
    expect(refused.status).toBe(400);
    expect(refused.body.code).toBe('expiry_not_changeable');
    const shown = await preview(prepared);
    expect(shown.status).toBe(200);
    expect(expiryOf(shown.body.signedMessage)).toBeGreaterThan(Date.now() + 6 * DAY_MS);
  });
});
