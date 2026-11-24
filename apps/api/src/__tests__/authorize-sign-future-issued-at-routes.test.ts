// TC-3920: the app chooses Issued At, so the signed end is counted from the earlier of Issued At and now: a later Issued At never moves the end past the caps measured from now.


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
    '../routes/delegate?authorize-sign-future-issued-at' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?authorize-sign-future-issued-at' as string
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

const ahead = (ms: number) => new Date(Date.now() + ms);
const pickIn = (ms: number) => new Date(Math.floor((Date.now() + ms) / 1000) * 1000).toISOString();
const SLACK_MS = 60_000;

describe('a later Issued At never lengthens a grant past its caps', () => {
  test('one-hour tier, no owner pick, Issued At 6 days ahead: refused as before, never signed for 145 hours', async () => {
    const prepared = await prepare(PREFIX_DECRYPT, 7 * DAY_MS, { issuedAt: ahead(6 * DAY_MS) });
    const shown = await preview(prepared);
    expect(shown.status).toBe(400);
    expect(shown.body.signedMessage).toBeUndefined();
  });

  test('owner picks 1 day, Issued At 20 hours ahead: the end is 1 day from now, not 44 hours', async () => {
    const bytes = await approve(PREFIX_DECRYPT, 7 * DAY_MS, { issuedAt: ahead(20 * HOUR_MS), ownerPicks: pickIn(DAY_MS) });
    expect(expiryOf(bytes)).toBeLessThanOrEqual(Date.now() + DAY_MS);
    expect(expiryOf(bytes)).toBeGreaterThan(Date.now() + DAY_MS - SLACK_MS);
  });

  test('an app that opts in to a changed expiry, Issued At 23 hours ahead, owner picks 1 day: the end is 1 day from now, not 47 hours', async () => {
    const bytes = await approve(NOTES_KV, 7 * DAY_MS, { expiryChangeable: true, issuedAt: ahead(23 * HOUR_MS), ownerPicks: pickIn(DAY_MS) });
    expect(expiryOf(bytes)).toBeLessThanOrEqual(Date.now() + DAY_MS);
    expect(expiryOf(bytes)).toBeGreaterThan(Date.now() + DAY_MS - SLACK_MS);
  });

  test('a backdated Issued At still counts the chosen length from Issued At', async () => {
    const issuedAt = ahead(-10 * 60_000);
    const bytes = await approve(NOTES_KV, 7 * DAY_MS, { expiryChangeable: true, issuedAt, ownerPicks: pickIn(DAY_MS) });
    expect(lengthOf(bytes)).toBe(DAY_MS);
    expect(expiryOf(bytes)).toBeLessThan(Date.now() + DAY_MS);
  });
});
