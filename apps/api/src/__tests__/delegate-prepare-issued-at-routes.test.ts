// /authorize-sign-prepare reads the requested SIWE's Issued At. The grant is signed to the Expiration Time and the
// length rules read Expiration Time minus Issued At, so an Issued At ahead of the clock by more than the skew is
// refused before any context is issued.
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { parseSiweFields, serializeSiwe } from '@openkey/capability-review';
import * as signing from '../services/authorization-signing';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import { mockModules, replaceModules } from './mock-module';

const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const space = `tinycloud:pkh:eip155:1:${account.address}:default`;
const managed = {
  id: 'managed_1', userId: user.id, address: account.address, keyType: 'MANAGED',
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};
const MINUTE_MS = 60_000;
const DAY_MS = 86_400_000;

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id: string; userId: string } }) =>
      where.id === managed.id && where.userId === user.id ? managed : null),
    findMany: mock(async () => [managed]),
    findUnique: mock(async () => managed),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
const unseal = mock(async () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const signManagedMessage = mock(async (message: string) => account.signMessage({ message }));
replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_test', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal,
    createWalletFromPrivateKey: () => ({ signMessage: ({ message }: { message: string }) => signManagedMessage(message) }),
    generatePrivateKey: () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    getAddressFromPrivateKey: () => account.address,
  }),
});

let router: typeof delegateRouter;
beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (with an isolating query) so the route binds the mocks above; a static import
  // would bind the real database and TEE first.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?prepare-issued-at-routes-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

beforeEach(() => {
  signing._resetAuthorizationContextStoreForTests();
  unseal.mockClear();
  signManagedMessage.mockClear();
});

function siweWith(issuedAtOffsetMs: number, expirationOffsetMs: number) {
  const now = Date.now();
  return prepareSession({
    address: account.address,
    chainId: 1,
    domain: 'openkey.so',
    issuedAt: new Date(now + issuedAtOffsetMs).toISOString(),
    expirationTime: new Date(now + expirationOffsetMs).toISOString(),
    spaceId: space,
    jwk,
    abilities: {
      kv: { [space]: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      capabilities: { [space]: ['tinycloud.capabilities/read'] },
    } as unknown as Parameters<typeof prepareSession>[0]['abilities'],
  }).siwe;
}

async function prepare(siwe: string) {
  const response = await router.request('/authorize-sign-prepare', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ keyId: managed.id, siwe, jwk, host, requestOrigin: 'https://openkey.so' }),
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

function nothingIssued(body: Record<string, unknown>) {
  expect(body.authorizationContextToken).toBeUndefined();
  expect(body.allowedActionIds).toBeUndefined();
  expect(unseal).not.toHaveBeenCalled();
  expect(signManagedMessage).not.toHaveBeenCalled();
}

describe('POST /authorize-sign-prepare reads Issued At', () => {
  test('refuses an Issued At 335 days ahead with an Expiration Time 365 days ahead', async () => {
    const result = await prepare(siweWith(335 * DAY_MS, 365 * DAY_MS));

    expect(result.status).toBe(400);
    expect(result.body.code).toBe('invalid_siwe_header');
    nothingIssued(result.body);
  });

  test('refuses an Issued At 6 minutes ahead and issues no context', async () => {
    const result = await prepare(siweWith(6 * MINUTE_MS, 6 * MINUTE_MS + 3_600_000));

    expect(result.status).toBe(400);
    expect(result.body.code).toBe('invalid_siwe_header');
    nothingIssued(result.body);
  });

  test('accepts an Issued At 4 minutes ahead', async () => {
    const result = await prepare(siweWith(4 * MINUTE_MS, 4 * MINUTE_MS + 3_600_000));

    expect(result.status).toBe(200);
    expect(typeof result.body.authorizationContextToken).toBe('string');
  });

  test('accepts an Issued At at the current time', async () => {
    const result = await prepare(siweWith(0, 3_600_000));

    expect(result.status).toBe(200);
    expect(typeof result.body.authorizationContextToken).toBe('string');
  });

  test('accepts an Issued At in the past with a 30 day Expiration Time', async () => {
    const result = await prepare(siweWith(-10 * MINUTE_MS, 30 * DAY_MS - 10 * MINUTE_MS));

    expect(result.status).toBe(200);
    expect(typeof result.body.authorizationContextToken).toBe('string');
  });
});

// The renewal lease counts its window from Not Before when the message has one, so a Not Before ahead of the clock
// moves the lease past the end the approval screen shows. It is refused at prepare, before any renewal choice is read.
function withNotBefore(siwe: string, notBeforeOffsetMs: number) {
  const parsed = parseSiweFields(siwe);
  if (!parsed.ok) throw new Error('the test SIWE must parse');
  return serializeSiwe({ ...parsed.fields, notBefore: new Date(Date.now() + notBeforeOffsetMs).toISOString() });
}

describe('POST /authorize-sign-prepare reads Not Before', () => {
  test('refuses a Not Before 335 days ahead with an Expiration Time 365 days ahead', async () => {
    const result = await prepare(withNotBefore(siweWith(0, 365 * DAY_MS), 335 * DAY_MS));

    expect(result.status).toBe(400);
    expect(result.body.code).toBe('invalid_siwe_header');
    expect(result.body.error).toBe('The SIWE Not Before is in the future. Set Not Before to the current time or remove it and send the request.');
    nothingIssued(result.body);
  });

  test('refuses a Not Before 6 minutes ahead and issues no context', async () => {
    const result = await prepare(withNotBefore(siweWith(0, 3_600_000), 6 * MINUTE_MS));

    expect(result.status).toBe(400);
    expect(result.body.code).toBe('invalid_siwe_header');
    nothingIssued(result.body);
  });

  test('accepts a Not Before 4 minutes ahead', async () => {
    const result = await prepare(withNotBefore(siweWith(0, 3_600_000), 4 * MINUTE_MS));

    expect(result.status).toBe(200);
    expect(typeof result.body.authorizationContextToken).toBe('string');
  });

  test('accepts a Not Before at the current time', async () => {
    const result = await prepare(withNotBefore(siweWith(0, 3_600_000), 0));

    expect(result.status).toBe(200);
    expect(typeof result.body.authorizationContextToken).toBe('string');
  });
});

describe('POST /authorize-sign-prepare words the Issued At refusal', () => {
  test('names Issued At and asks to send the request', async () => {
    const result = await prepare(siweWith(6 * MINUTE_MS, 6 * MINUTE_MS + 3_600_000));

    expect(result.body.error).toBe('The SIWE Issued At is in the future. Set Issued At to the current time and send the request.');
  });
});
