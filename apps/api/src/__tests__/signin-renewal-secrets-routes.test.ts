// TC-3821: renewal at an app sign-in on a grant that reaches secrets. The app's renewal ask alone, or a bare leased
// choice, never sets up a lease: the preview refuses it unless the owner confirmed "Renew sensitive access?" and the
// grant's window is at most 7 days, and approving cannot add the confirm the preview did not seal. The delegate routes
// run in-process with a managed key that really signs, and a loopback stand-in node that only answers who its renewer is.
import { beforeAll, afterAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { SiweMessage } from 'siwe';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import * as signing from '../services/authorization-signing';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import { mockModules, replaceModules } from './mock-module';

const DAY = 86_400;
const NODE = 'http://127.0.0.1:8124';
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const RENEWER_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const RENEWER_PUBLIC_KEY = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik';
const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const owner = { id: 'owner_1', email: 'owner@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } as const;
const space = `tinycloud:pkh:eip155:1:${account.address}:default`;
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${account.address}:default`;
const managed = { id: 'managed_1', userId: owner.id, address: account.address, keyType: 'MANAGED', archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null };

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id: string; userId: string } }) => where.id === managed.id && where.userId === owner.id ? managed : null),
    findMany: mock(async () => [managed]),
    findUnique: mock(async () => managed),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
  get renewalLease(): never { throw new Error('a sign-in touched the renewal lease table'); },
  $transaction: () => { throw new Error('a sign-in opened a database transaction'); },
};
const signManagedMessage = mock(async (message: string) => account.signMessage({ message }));
const reserveRenewalLease = mock(async (): Promise<void> => undefined);

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', owner);
      c.set('session', { id: 'session_owner', userId: owner.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
    createWalletFromPrivateKey: () => ({ signMessage: ({ message }: { message: string }) => signManagedMessage(message) }),
    generatePrivateKey: () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    getAddressFromPrivateKey: () => account.address,
  }),
  '../services/renewal-lease-revocation': () => ({ reserveRenewalLease }),
});

const realFetch = globalThis.fetch;
let nodeCalls: string[] = [];
let router: typeof delegateRouter;
const savedFlag = process.env.OPENKEY_RENEWAL_LEASES;
beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Static import cannot work: the route captures its database client and TEE when it loads, after the mocks above.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import('../routes/delegate?signin-renewal-secrets-routes' as string));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', owner);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: owner.id });
    c.set('session', { id: 'session_owner', userId: owner.id, expiresAt: new Date(Date.now() + 60_000) });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});
afterAll(() => {
  globalThis.fetch = realFetch;
  if (savedFlag === undefined) delete process.env.OPENKEY_RENEWAL_LEASES;
  else process.env.OPENKEY_RENEWAL_LEASES = savedFlag;
});
beforeEach(() => {
  signing._resetAuthorizationContextStoreForTests();
  process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
  nodeCalls = [];
  signManagedMessage.mockClear();
  reserveRenewalLease.mockClear();
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin !== NODE) throw new Error(`unexpected ${url.href}`);
    nodeCalls.push(`${init?.method ?? 'GET'} ${url.pathname}`);
    if (url.pathname === '/info') return Response.json({ nodeId: NODE_DID });
    if (url.pathname === '/.well-known/tinycloud/node-keys') {
      return Response.json({ nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 });
    }
    throw new Error(`unexpected node call ${init?.method ?? 'GET'} ${url.href}`);
  }) as typeof fetch;
});

async function post(path: string, body: unknown) {
  const response = await router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() as Record<string, any> };
}

/** The app's grant: a KV read plus `rawAbilities`, for 30 days from its issued-at (whole seconds). */
function grantSiwe(rawAbilities: Record<string, string[]>) {
  const issuedAt = Math.floor(Date.now() / 1000) * 1000;
  return prepareSession({
    address: account.address, chainId: 1, domain: 'openkey.so', spaceId: space, jwk,
    issuedAt: new Date(issuedAt).toISOString(), expirationTime: new Date(issuedAt + 30 * DAY * 1000).toISOString(),
    abilities: { kv: { [space]: ['tinycloud.kv/get'] } },
    rawAbilities,
  } as unknown as Parameters<typeof prepareSession>[0]).siwe;
}

type Prepared = { authorizationContextToken: string; allowedActionIds: string[]; renewal?: unknown; siwe: string };

async function prepare(rawAbilities: Record<string, string[]>): Promise<Prepared> {
  const siwe = grantSiwe(rawAbilities);
  const prepared = await post('/authorize-sign-prepare', {
    keyId: managed.id, siwe, jwk, host: NODE, requestOrigin: 'https://openkey.so', expiryChangeable: true,
    renewal: { version: 1, leaseLifetimeSeconds: 90 * DAY },
  });
  expect(prepared.status).toBe(200);
  expect(prepared.body.renewal).toEqual({ leaseLifetimeSeconds: 90 * DAY });
  return { ...(prepared.body as Omit<Prepared, 'siwe'>), siwe };
}

/** The preview with every permission kept and every extra permission allowed on the warning screen. */
async function preview(p: Prepared, renewal: unknown, windowSeconds?: number) {
  const issuedAt = Date.parse(new SiweMessage(p.siwe).issuedAt!);
  return post('/authorize-sign-preview', {
    authorizationContextToken: p.authorizationContextToken, selectedActionIds: p.allowedActionIds,
    elevatedDecision: { allowed: p.allowedActionIds }, renewal,
    ...(windowSeconds === undefined ? {} : { expirationTime: new Date(issuedAt + windowSeconds * 1000).toISOString() }),
  });
}

async function sign(p: Prepared, previewBody: Record<string, any>, extra: Record<string, unknown> = {}) {
  return post('/authorize-sign', {
    authorizationContextToken: p.authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken,
    selectedActionIds: p.allowedActionIds, elevatedDecision: { allowed: p.allowedActionIds }, protocolVersion: 1, ...extra,
  });
}

const LEASED = { choice: 'leased', leaseLifetimeSeconds: 90 * DAY };
const CONFIRMED = { ...LEASED, sensitiveConfirmed: true };
const SECRET_DECRYPT = { [`${network}/secrets/openai_api_key`]: ['tinycloud.encryption/decrypt'] };
const NETWORK_DECRYPT = { [network]: ['tinycloud.encryption/decrypt'] };

describe('an app-asked lease on a grant that reaches secrets', () => {
  for (const [name, abilities] of [['a secrets/ key', SECRET_DECRYPT], ['the whole network', NETWORK_DECRYPT]] as const) {
    test(`decrypt on ${name}: a bare leased choice is refused at the preview; nothing is signed or asked`, async () => {
      const asked = await prepare(abilities);
      for (const window of [undefined, 7 * DAY]) {
        const shown = await preview(asked, LEASED, window);
        expect(shown).toMatchObject({ status: 400, body: { code: 'renewal_refused' } });
        expect(shown.body).not.toHaveProperty('previewApprovalToken');
      }
      expect(signManagedMessage).not.toHaveBeenCalled();
      expect(reserveRenewalLease).not.toHaveBeenCalled();
      expect(nodeCalls).toEqual([]);
    });
  }

  test('the finite choice still signs in, without a lease', async () => {
    const asked = await prepare(SECRET_DECRYPT);
    const shown = await preview(asked, { choice: 'finite' });
    expect(shown.status).toBe(200);
    const signed = await sign(asked, shown.body);
    expect(signed.status).toBe(200);
    expect(signed.body).not.toHaveProperty('renewal');
    expect(reserveRenewalLease).not.toHaveBeenCalled();
  });
});

describe('the owner confirmed renewing sensitive access', () => {
  test('a 7-day window is sealed with the confirm and signed with an owner lease of the chosen length', async () => {
    const asked = await prepare(SECRET_DECRYPT);
    const shown = await preview(asked, CONFIRMED, 7 * DAY);
    expect(shown.status).toBe(200);
    expect(shown.body.renewal).toEqual(CONFIRMED);
    const signed = await sign(asked, shown.body);
    expect(signed.status).toBe(200);
    const message = new SiweMessage(signed.body.signedMessage);
    expect(Date.parse(message.expirationTime!) - Date.parse(message.issuedAt!)).toBe(7 * DAY * 1000);
    expect(signed.body.renewal.approvedLeaseLifetimeSeconds).toBe(90 * DAY);
    expect(Date.parse(signed.body.renewal.receipt.leaseExpiresAt) - Date.parse(signed.body.renewal.approvedAt)).toBe(90 * DAY * 1000);
    expect(reserveRenewalLease).toHaveBeenCalledTimes(1);
  });

  test("a window over 7 days is refused, the app's own 30 days included", async () => {
    const asked = await prepare(NETWORK_DECRYPT);
    for (const window of [undefined, 7 * DAY + 1, 8 * DAY]) {
      expect(await preview(asked, CONFIRMED, window)).toMatchObject({ status: 400, body: { code: 'renewal_refused' } });
    }
    expect(signManagedMessage).not.toHaveBeenCalled();
  });
});

describe('approving cannot add the confirm the preview did not seal', () => {
  test('an approve body naming the confirm over a bare sealed lease is refused before signing', async () => {
    const asked = await prepare({});
    const shown = await preview(asked, LEASED);
    expect(shown.status).toBe(200);
    expect(shown.body.renewal).toEqual(LEASED);
    const signed = await sign(asked, shown.body, { renewal: CONFIRMED });
    expect(signed).toMatchObject({ status: 400, body: { code: 'request_binding' } });
    expect(signManagedMessage).not.toHaveBeenCalled();
  });
});

describe('an ordinary grant is unchanged', () => {
  test('a KV-only lease needs no confirm and keeps its 30-day window', async () => {
    const asked = await prepare({});
    const shown = await preview(asked, LEASED);
    expect(shown.status).toBe(200);
    const signed = await sign(asked, shown.body);
    expect(signed.status).toBe(200);
    const message = new SiweMessage(signed.body.signedMessage);
    expect(Date.parse(message.expirationTime!) - Date.parse(message.issuedAt!)).toBe(30 * DAY * 1000);
    expect(signed.body.renewal.approvedLeaseLifetimeSeconds).toBe(90 * DAY);
  });
});
