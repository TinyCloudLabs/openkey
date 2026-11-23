// In the frame (/authorize-sign-prepare, /authorize-sign-preview, /authorize-sign) a KV resource written `<space>/kv`
// (no path, the whole space) keeps the lifetime the app asked or the owner picked, like `<space>/kv/` and another
// folder. A read of the secrets vault is brought back to 7 days from now.

import './tc1777-test-env';
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
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
const SPACE = `tinycloud:pkh:eip155:1:${address}:applications`;
const HOST = 'https://node.tinycloud.xyz';
const DAY_MS = 86_400_000;
const KV = 'tinycloud.kv/';

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
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
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
    '../routes/delegate?authorize-sign-kv-space-root-lifetime' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?authorize-sign-kv-space-root-lifetime' as string
  ));
});

beforeEach(() => {
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
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
    rawAbilities,
  }).siwe;
}

function post(path: string, body: unknown) {
  return router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
}

const expiryOf = (siwe: string) => Date.parse(/^Expiration Time: (.+)$/m.exec(siwe)?.[1] ?? '');

const HOUR_MS = 3_600_000;

function expectLifetime(bytes: string, before: number, lifetimeMs: number) {
  const expiry = expiryOf(bytes);
  expect(expiry).toBeGreaterThanOrEqual(before + lifetimeMs - 1000);
  expect(expiry).toBeLessThanOrEqual(Date.now() + lifetimeMs);
}

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
    elevatedDecision: { allowed: [] },
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

const WHOLE_SPACE_SHAPES: Array<[string, Record<string, string[]>]> = [
  ['get, list, put, del and metadata on <space>/kv', { [`${SPACE}/kv`]: ['get', 'list', 'put', 'del', 'metadata'].map((verb) => `${KV}${verb}`) }],
  ['sync on <space>/kv', { [`${SPACE}/kv`]: [`${KV}sync`] }],
];

describe('the frame leaves a KV grant on the whole space at the lifetime asked', () => {
  test.each(WHOLE_SPACE_SHAPES)("%s: the app's 30 days are signed as 30", async (_name, raw) => {
    const before = Date.now();
    expect(expiryOf(await approve(raw, 30 * DAY_MS))).toBeGreaterThan(before + 29 * DAY_MS);
  });

  test.each(WHOLE_SPACE_SHAPES)("%s: the owner's 30 days are signed as 30", async (_name, raw) => {
    const before = Date.now();
    const ownerPicks = new Date(Math.floor((Date.now() + 30 * DAY_MS) / 1000) * 1000).toISOString();
    const bytes = await approve(raw, DAY_MS, { expiryChangeable: true, ownerPicks });
    expect(expiryOf(bytes)).toBe(Date.parse(ownerPicks));
    expect(expiryOf(bytes)).toBeGreaterThan(before + 29 * DAY_MS);
  });
});

describe('the frame holds a KV read of the secrets vault to 7 days', () => {
  test.each([
    ['get on <space>/kv/vault/secrets/', { [`${SPACE}/kv/vault/secrets/`]: [`${KV}get`] }, HOUR_MS],
    ['get on <space>/kv/secrets/x', { [`${SPACE}/kv/secrets/x`]: [`${KV}get`] }, 7 * DAY_MS],
    ['a whole-space read with a vault read beside it', { [`${SPACE}/kv`]: [`${KV}get`], [`${SPACE}/kv/vault/secrets/`]: [`${KV}get`] }, HOUR_MS],
  ] as Array<[string, Record<string, string[]>, number]>)("%s: the app's 30 days are signed for the expected lifetime", async (_name, raw, lifetimeMs) => {
    const before = Date.now();
    expectLifetime(await approve(raw, 30 * DAY_MS), before, lifetimeMs);
  });
});

describe('the frame previews the same request twice, as when the owner changes the renewal box', () => {
  async function signAfterTwoPreviews(raw: Record<string, string[]>, lifetimeMs: number) {
    const prepared = await post('/authorize-sign-prepare', {
      keyId: keyRecord.id, siwe: siweFor(raw, lifetimeMs), jwk, host: HOST, requestOrigin: ORIGIN, reportedOrigin: ORIGIN,
    });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
    const previews: Array<{ previewApprovalToken: string; signedMessage: string }> = [];
    for (let i = 0; i < 2; i += 1) {
      const preview = await post('/authorize-sign-preview', { authorizationContextToken, selectedActionIds: allowedActionIds, elevatedDecision: { allowed: [] } });
      expect(preview.status, await preview.clone().text()).toBe(200);
      previews.push(await preview.json() as { previewApprovalToken: string; signedMessage: string });
    }
    const last = previews[1]!;
    const res = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken: last.previewApprovalToken, selectedActionIds: allowedActionIds, protocolVersion: 1 });
    expect(res.status, await res.clone().text()).toBe(200);
    const { signedMessage } = await res.json() as { signedMessage: string };
    expect(signedMessage).toBe(last.signedMessage);
    return { first: previews[0]!.signedMessage, signedMessage };
  }

  test('<space>/kv: both previews and the signed bytes carry the 30 days the app asked', async () => {
    const before = Date.now();
    const { first, signedMessage } = await signAfterTwoPreviews({ [`${SPACE}/kv`]: ['get', 'list', 'put', 'del', 'metadata'].map((verb) => `${KV}${verb}`) }, 30 * DAY_MS);
    expect(expiryOf(first)).toBeGreaterThan(before + 29 * DAY_MS);
    expect(expiryOf(signedMessage)).toBeGreaterThan(before + 29 * DAY_MS);
  });

  test('a vault-secrets read: both previews and the signed bytes carry one hour', async () => {
    const before = Date.now();
    const { first, signedMessage } = await signAfterTwoPreviews({ [`${SPACE}/kv/vault/secrets/`]: [`${KV}get`] }, 30 * DAY_MS);
    for (const bytes of [first, signedMessage]) {
      expectLifetime(bytes, before, HOUR_MS);
    }
  });
});

// The owner can preview a request several times (the renewal box, the expiry field) and sign any selection of it.
// Whatever the sequence, bytes that read secrets are signed for 7 days at most. A whole network's `decrypt` is
// held only with OPENKEY_NETWORK_DECRYPT_CAP=enabled, which is off by default.
const OWNER = `did:pkh:eip155:1:${address}`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';
const elevatedIds = (allowed: string[]) =>
  allowed.filter((id) => id.includes('urn:tinycloud:encryption:') && /\0(tinycloud\.)?encryption\/(decrypt|key\.create)$/.test(id));

interface Sequence {
  /** How many previews come before the one that is signed: 0 signs the first. */
  extraPreviews?: number;
  /** The expiry the owner picks on every preview, if any. */
  ownerPicks?: string;
  /** Sign with the first preview's token after the later ones were issued. */
  signFirst?: boolean;
  /** Keep only the actions whose id contains this text. */
  only?: string;
}

async function signSequence(raw: Record<string, string[]>, lifetimeMs: number, sequence: Sequence = {}) {
  const prepared = await post('/authorize-sign-prepare', {
    keyId: keyRecord.id, siwe: siweFor(raw, lifetimeMs), jwk, host: HOST, requestOrigin: ORIGIN, reportedOrigin: ORIGIN,
    expiryChangeable: true,
  });
  expect(prepared.status, await prepared.clone().text()).toBe(200);
  const { authorizationContextToken, allowedActionIds } = await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
  const selected = sequence.only === undefined ? allowedActionIds : allowedActionIds.filter((id) => id.includes(sequence.only!));
  expect(selected.length).toBeGreaterThan(0);
  const previews: Array<{ previewApprovalToken: string; signedMessage: string }> = [];
  for (let i = 0; i <= (sequence.extraPreviews ?? 0); i += 1) {
    const preview = await post('/authorize-sign-preview', {
      authorizationContextToken,
      selectedActionIds: selected,
      elevatedDecision: { allowed: elevatedIds(selected) },
      ...(sequence.ownerPicks === undefined ? {} : { expirationTime: sequence.ownerPicks }),
    });
    expect(preview.status, await preview.clone().text()).toBe(200);
    previews.push(await preview.json() as { previewApprovalToken: string; signedMessage: string });
  }
  const chosen = sequence.signFirst ? previews[0]! : previews[previews.length - 1]!;
  const res = await post('/authorize-sign', {
    authorizationContextToken, previewApprovalToken: chosen.previewApprovalToken, selectedActionIds: selected, protocolVersion: 1,
  });
  expect(res.status, await res.clone().text()).toBe(200);
  const { signedMessage } = await res.json() as { signedMessage: string };
  expect(signedMessage).toBe(chosen.signedMessage);
  return { signedMessage, previews };
}

const SEQUENCES: Array<[string, Sequence]> = [
  ['one preview, the app\'s 30 days', {}],
  ['two previews, the app\'s 30 days, signed with the last', { extraPreviews: 1 }],
  ['two previews, the app\'s 30 days, signed with the first', { extraPreviews: 1, signFirst: true }],
  ['two previews, the owner picks 30 days', { extraPreviews: 1, ownerPicks: new Date(Math.floor((Date.now() + 30 * DAY_MS) / 1000) * 1000).toISOString() }],
];

const READS_OF_SECRETS: Array<[string, Record<string, string[]>, number]> = [
  ['get on <space>/kv/vault/secrets/OPENAI_API_KEY', { [`${SPACE}/kv/vault/secrets/OPENAI_API_KEY`]: [`${KV}get`] }, 7 * DAY_MS],
  ['list on <space>/kv/vault/secrets/', { [`${SPACE}/kv/vault/secrets/`]: [`${KV}list`] }, 7 * DAY_MS],
  ['decrypt on default/secrets/openai_api_key', { [urn('/secrets/openai_api_key')]: [`${E}decrypt`] }, 7 * DAY_MS],
  ['key.create on default/secrets/openai_api_key', { [urn('/secrets/openai_api_key')]: [`${E}key.create`] }, 7 * DAY_MS],
  ['decrypt on default/secrets/', { [urn('/secrets/')]: [`${E}decrypt`] }, HOUR_MS],
];

describe('no sequence of previews signs a read of secrets for more than 7 days', () => {
  for (const [read, raw, defaultLifetimeMs] of READS_OF_SECRETS) {
    test.each(SEQUENCES)(`${read}: %s`, async (_name, sequence) => {
      const before = Date.now();
      const { signedMessage, previews } = await signSequence(raw, 30 * DAY_MS, sequence);
      for (const bytes of [signedMessage, ...previews.map((preview) => preview.signedMessage)]) {
        expectLifetime(bytes, before, sequence.ownerPicks === undefined ? defaultLifetimeMs : 7 * DAY_MS);
      }
    });
  }
});

describe('a selection of a request that reads the vault and the whole space', () => {
  const both = { [`${SPACE}/kv`]: [`${KV}get`, `${KV}list`], [`${SPACE}/kv/vault/secrets/`]: [`${KV}get`] };

  test('only the vault read: signed for one hour', async () => {
    const before = Date.now();
    const { signedMessage } = await signSequence(both, 30 * DAY_MS, { extraPreviews: 1, only: 'vault/secrets' });
    expectLifetime(signedMessage, before, HOUR_MS);
  });

  test('every action: signed for one hour', async () => {
    const before = Date.now();
    const { signedMessage } = await signSequence(both, 30 * DAY_MS, { extraPreviews: 1 });
    expectLifetime(signedMessage, before, HOUR_MS);
  });
});

describe('a whole network decrypt, with the network cap off (the default)', () => {
  test.each(SEQUENCES)('%s: signed for one hour without an owner pick, the pick otherwise', async (_name, sequence) => {
    const before = Date.now();
    const { signedMessage } = await signSequence({ [urn('')]: [`${E}decrypt`] }, 30 * DAY_MS, sequence);
    if (sequence.ownerPicks === undefined) {
      expectLifetime(signedMessage, before, HOUR_MS);
    } else {
      expect(expiryOf(signedMessage)).toBe(Date.parse(sequence.ownerPicks));
    }
  });
});
