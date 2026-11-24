// A sign-in whose grants reach all secrets or all encrypted data (the one-hour tier, `grantIsBroadOnce`) is
// expiry-changeable whatever the app sends, and an approval with no owner pick starts at one hour: the preview
// writes the hour into the bytes, those are the bytes signed, and the owner may choose longer up to the 7-day cap.
// Grants outside the tier keep the app's own time and the `expiry_not_changeable` refusal.

import './tc1777-test-env';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, setSystemTime, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { verifyMessage } from 'ethers';
import { mockModules, replaceModules } from './mock-module';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { SiweMessage } from 'siwe';

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
const NODE = 'http://127.0.0.1:8125';
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const RENEWER_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const RENEWER_PUBLIC_KEY = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik';

const unsealMock = mock(async () => privateKey);
let signed: string[] = [];
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
  get renewalLease(): never { throw new Error('a sign-in touched the renewal lease table'); },
  $transaction: () => { throw new Error('a sign-in opened a database transaction'); },
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
const reserveRenewalLease = mock(async (): Promise<void> => undefined);
await mockModules({
  '../services/renewal-lease-revocation': () => ({ reserveRenewalLease }),
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

const realFetch = globalThis.fetch;
const savedLeasesFlag = process.env.OPENKEY_RENEWAL_LEASES;
afterAll(() => {
  globalThis.fetch = realFetch;
  if (savedLeasesFlag === undefined) delete process.env.OPENKEY_RENEWAL_LEASES;
  else process.env.OPENKEY_RENEWAL_LEASES = savedLeasesFlag;
});

beforeEach(() => {
  signed = [];
  unsealMock.mockClear();
  reserveRenewalLease.mockClear();
  resetContexts?.();
  process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin !== NODE) return realFetch(input, init);
    if (url.pathname === '/info') return Response.json({ nodeId: NODE_DID });
    if (url.pathname === '/.well-known/tinycloud/node-keys') {
      return Response.json({ nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 });
    }
    throw new Error(`unexpected node call ${init?.method ?? 'GET'} ${url.href}`);
  }) as typeof fetch;
});

function siweFor(rawAbilities: Record<string, string[]>, lifetimeMs: number, issuedAt?: Date): string {
  const now = issuedAt ?? new Date();
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
/** The signed length: Expiration Time minus Issued At (TC-3920). */
const lengthOf = (siwe: string) => expiryOf(siwe) - Date.parse(/^Issued At: (.+)$/m.exec(siwe)?.[1] ?? '');
const elevatedIds = (allowed: string[]) =>
  allowed.filter((id) => id.includes('urn:tinycloud:encryption:') && /\0(tinycloud\.)?encryption\/(decrypt|key\.create)$/.test(id));

type Prepared = { authorizationContextToken: string; allowedActionIds: string[]; siwe: string };

async function prepare(raw: Record<string, string[]>, lifetimeMs: number, opts: { expiryChangeable?: boolean; host?: string; renewal?: unknown; issuedAt?: Date } = {}) {
  const siwe = siweFor(raw, lifetimeMs, opts.issuedAt);
  const prepared = await post('/authorize-sign-prepare', {
    keyId: keyRecord.id, siwe, jwk, host: opts.host ?? HOST, requestOrigin: ORIGIN, reportedOrigin: ORIGIN,
    ...(opts.expiryChangeable ? { expiryChangeable: true } : {}),
    ...(opts.renewal === undefined ? {} : { renewal: opts.renewal }),
  });
  expect(prepared.status, await prepared.clone().text()).toBe(200);
  return { ...(await prepared.json()) as { authorizationContextToken: string; allowedActionIds: string[] }, siwe };
}

async function preview(prepared: Prepared, ownerPicks?: string, selectedActionIds?: string[], renewal?: unknown) {
  const res = await post('/authorize-sign-preview', {
    authorizationContextToken: prepared.authorizationContextToken,
    selectedActionIds: selectedActionIds ?? prepared.allowedActionIds,
    elevatedDecision: { allowed: elevatedIds(prepared.allowedActionIds) },
    ...(ownerPicks === undefined ? {} : { expirationTime: ownerPicks }),
    ...(renewal === undefined ? {} : { renewal }),
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
    expect(lengthOf(await approve(raw, 7 * DAY_MS, { ownerPicks: picked }))).toBe(7 * DAY_MS);
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
    expect(lengthOf(await approve(PREFIX_DECRYPT, 7 * DAY_MS, { expiryChangeable: true, ownerPicks: picked }))).toBe(7 * DAY_MS);
  });

  test('a pick of 30 days with the opt-in is signed as 7 days', async () => {
    const before = Date.now();
    const picked = new Date(Date.now() + 30 * DAY_MS).toISOString();
    const expiry = expiryOf(await approve(PREFIX_DECRYPT, 7 * DAY_MS, { expiryChangeable: true, ownerPicks: picked }));
    expect(expiry).toBeGreaterThan(before + 7 * DAY_MS - 60_000);
    expect(expiry).toBeLessThanOrEqual(Date.now() + 7 * DAY_MS);
  });
});

// The one-time length choice on the approval screen (TC-4156) sends an explicit length for every option. These are the
// lengths it sends, and the length each one is signed with; a request with no length at all is signed as one hour.
describe('the one-time choice signs exactly the length it sends', () => {
  const savedNetworkCap = process.env.OPENKEY_NETWORK_DECRYPT_CAP;
  afterEach(() => {
    if (savedNetworkCap === undefined) delete process.env.OPENKEY_NETWORK_DECRYPT_CAP;
    else process.env.OPENKEY_NETWORK_DECRYPT_CAP = savedNetworkCap;
  });

  test.each([
    ['the 1 hour option', NETWORK_DECRYPT, 7, HOUR_MS / DAY_MS],
    ['the asked length, 3 days, within the cap', NETWORK_DECRYPT, 3, 3],
    ['the asked length, exactly the 7-day cap', NETWORK_DECRYPT, 7, 7],
    ['the longest allowed when the app asked for 30 days', NETWORK_DECRYPT, 30, 7],
    ['the longest allowed on the secrets/ prefix', PREFIX_DECRYPT, 30, 7],
  ] as const)('%s', async (_name, raw, askedDays, pickDays) => {
    delete process.env.OPENKEY_NETWORK_DECRYPT_CAP;
    const picked = new Date(Math.floor((Date.now() + pickDays * DAY_MS) / 1000) * 1000).toISOString();
    const signedBytes = await approve(raw, askedDays * DAY_MS, { ownerPicks: picked });
    expect(expiryOf(signedBytes)).toBe(Date.parse(picked));
  });

  test('a preview with no length is signed as one hour, not as the 3 days the app asked for', async () => {
    const before = Date.now();
    expectAboutOneHour(await approve(NETWORK_DECRYPT, 3 * DAY_MS), before);
  });

  test.each([
    ['all encrypted data', NETWORK_DECRYPT],
    ['the secrets/ prefix', PREFIX_DECRYPT],
  ] as const)('a 30-day pick on %s is signed as the 7-day limit, not as 30 days', async (_name, raw) => {
    delete process.env.OPENKEY_NETWORK_DECRYPT_CAP;
    const before = Date.now();
    const picked = new Date(before + 30 * DAY_MS).toISOString();
    const expiry = expiryOf(await approve(raw, 30 * DAY_MS, { ownerPicks: picked }));
    expect(expiry).toBeGreaterThanOrEqual(before + 7 * DAY_MS - 1000);
    expect(expiry).toBeLessThanOrEqual(Date.now() + 7 * DAY_MS);
  });
});

describe('an owner pick on the broad tier is limited to seven days', () => {
  const outsideAppPrefix = { [urn('/qa/')]: [`${E}decrypt`] };

  const savedNetworkCap = process.env.OPENKEY_NETWORK_DECRYPT_CAP;
  afterEach(() => {
    if (savedNetworkCap === undefined) delete process.env.OPENKEY_NETWORK_DECRYPT_CAP;
    else process.env.OPENKEY_NETWORK_DECRYPT_CAP = savedNetworkCap;
  });

  test.each([
    ['network decrypt, no opt-in, 365 days', NETWORK_DECRYPT, false, 365],
    ['network decrypt, opted in, 30 days', NETWORK_DECRYPT, true, 30],
    ['non-app prefix, no opt-in, 365 days', outsideAppPrefix, false, 365],
    ['non-app prefix, opted in, 365 days', outsideAppPrefix, true, 365],
  ] as const)('%s: previews and signs seven days', async (_name, raw, expiryChangeable, days) => {
    delete process.env.OPENKEY_NETWORK_DECRYPT_CAP;
    const before = Date.now();
    const picked = new Date(before + days * DAY_MS).toISOString();
    const expiry = expiryOf(await approve(raw, 7 * DAY_MS, { expiryChangeable, ownerPicks: picked }));
    expect(expiry).toBeGreaterThanOrEqual(before + 7 * DAY_MS - 1000);
    expect(expiry).toBeLessThanOrEqual(Date.now() + 7 * DAY_MS);
  });

  test('an owner pick of three days previews and signs exactly three days', async () => {
    const picked = new Date(Date.now() + 3 * DAY_MS).toISOString();
    expect(expiryOf(await approve(NETWORK_DECRYPT, 7 * DAY_MS, { ownerPicks: picked }))).toBe(Date.parse(picked));
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

const CONFIRMED_LEASE = { choice: 'leased', leaseLifetimeSeconds: 90 * 86_400, sensitiveConfirmed: true };

describe('a chosen renewal keeps the app\'s own time', () => {
  // Standing access is an owner choice: with a lease chosen and no expiry picked the preview gets the app's
  // own window, so `assertLeaseableGrant` holds it to 7 days and a longer ask is refused rather than signed short.
  async function leasePrepare(raw: Record<string, string[]>, lifetimeMs: number) {
    // Issued one minute ago so a capped window (now + 7 days, measured from issued-at) is over 7 days at
    // every millisecond the preview could run.
    const prepared = await prepare(raw, lifetimeMs, {
      expiryChangeable: true, host: NODE, issuedAt: new Date(Date.now() - 60_000),
      renewal: { version: 1, leaseLifetimeSeconds: 90 * 86_400 },
    });
    return prepared;
  }

  test.each([
    ['decrypt on the secrets/ prefix', PREFIX_DECRYPT],
    ['decrypt on the whole network', NETWORK_DECRYPT],
  ])('%s: a confirmed lease on a 30-day request is refused, not signed for an hour', async (_name, raw) => {
    const prepared = await leasePrepare(raw, 30 * DAY_MS);
    const shown = await preview(prepared, undefined, undefined, CONFIRMED_LEASE);
    expect(shown).toMatchObject({ status: 400, body: { code: 'renewal_refused' } });
    expect(signed).toEqual([]);
  });

  test("a confirmed lease refuses the app's 30-day window even when the secret cap would fit", async () => {
    const issuedAt = new Date();
    setSystemTime(issuedAt);
    try {
      const prepared = await prepare(PREFIX_DECRYPT, 30 * DAY_MS, {
        expiryChangeable: true, host: NODE, issuedAt, renewal: { version: 1, leaseLifetimeSeconds: 90 * 86_400 },
      });
      const shown = await preview(prepared, undefined, undefined, CONFIRMED_LEASE);
      expect(shown).toMatchObject({ status: 400, body: { code: 'renewal_refused' } });
      expect(signed).toEqual([]);
    } finally {
      setSystemTime();
    }
  });

  test('a confirmed lease with a window of 7 days signs that window', async () => {
    const prepared = await leasePrepare(PREFIX_DECRYPT, 30 * DAY_MS);
    const issuedAt = Date.parse(new SiweMessage(prepared.siwe).issuedAt!);
    const window = new Date(issuedAt + 7 * DAY_MS).toISOString();
    const shown = await preview(prepared, window, undefined, CONFIRMED_LEASE);
    expect(shown.status, JSON.stringify(shown.body)).toBe(200);
    expect(expiryOf(shown.body.signedMessage)).toBe(Date.parse(window));
    const res = await post('/authorize-sign', {
      authorizationContextToken: prepared.authorizationContextToken,
      previewApprovalToken: shown.body.previewApprovalToken,
      selectedActionIds: prepared.allowedActionIds,
      protocolVersion: 1,
      renewal: CONFIRMED_LEASE,
    });
    expect(res.status, await res.clone().text()).toBe(200);
    const result = await res.json() as { signedMessage: string; signature: string };
    expect(result.signedMessage).toBe(shown.body.signedMessage);
    expect(expiryOf(result.signedMessage)).toBe(Date.parse(window));
    expect(verifyMessage(result.signedMessage, result.signature)).toBe(address);
  });
});
