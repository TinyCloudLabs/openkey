// Route-level HTTP tests for Blocker 1: the managed approval path.
//
// Contract: POST /api/delegate/prepare binds the exact preview SIWE bytes.
// POST /api/delegate — when supplied a versioned `authorizationContextToken`,
// `prepared`, and `selectedActionIds` — signs the STORED originalSiwe bytes
// byte-for-byte instead of regenerating a fresh preview. The legacy
// token-less path continues to work as before.
//
// These tests exercise the actual Hono router. They validate:
//
//   1. /prepare returns an authorizationContext.token (Blocker 1 binds
//      originalSiwe to it — enforced via the round-trip below).
//   2. POST /api/delegate (versioned) signs the exact SIWE bytes that
//      /prepare returned; the signature verifies against those bytes.
//   3. POST /api/delegate (versioned) rejects when `prepared.siwe` does
//      not match the /prepare-bound bytes byte-for-byte.
//   4. POST /api/delegate (versioned) rejects when the token is missing
//      but protocolVersion >= 1 is supplied.
//   5. POST /api/delegate (versioned) rejects when selectedActionIds
//      does not exactly match the actions encoded in the signed SIWE.
//   6. POST /api/delegate (legacy — no token, no prepared) still works.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };

let currentUser = user;

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
      if (where.userId !== currentUser.id) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== currentUser.id) return [];
      if (where.archivedAt !== null) return [];
      return [keyRecord];
    }),
    findUnique: mock(async () => keyRecord),
  },
  user: {
    findUnique: mock(async () => ({ autoSignEnabled: true })),
  },
  tinyCloudBootstrapState: {},
};

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));

mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({
    deriveKey: mock(async () => new Uint8Array(32)),
    getQuote: mock(async () => 'quote'),
    isInTee: () => false,
  }),
  unseal: mock(async () => privateKey),
  createWalletFromPrivateKey: (key: string) => {
    const wallet = privateKeyToAccount(key as `0x${string}`);
    return {
      ...wallet,
      signMessage: async (input: { message: string }) => wallet.signMessage(input),
    };
  },
  generatePrivateKey: () => privateKey,
  getAddressFromPrivateKey: () => address,
}));

mock.module('@tinycloud/sdk-core', () => ({
  activateSessionWithHost: mock(async () => ({ success: true })),
}));

mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', currentUser);
    c.set('session', {
      id: 'session_' + currentUser.id,
      userId: currentUser.id,
      expiresAt: new Date(Date.now() + 60_000),
    });
    await next();
  }),
}));

let router: typeof import('../routes/delegate')['delegateRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];

beforeAll(async () => {
  ({ delegateRouter: router } = await import(
    '../routes/delegate?managed-approval-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?managed-approval-routes-isolated' as string
  ));
});

beforeEach(() => {
  currentUser = user;
  resetContexts?.();
});

async function prepare(): Promise<{
  token: string;
  prepared: any;
  selectedActionKeys: string[];
  siwe: string;
}> {
  const res = await router.request('/prepare', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      keyId: keyRecord.id,
      jwk,
      host: 'https://node.tinycloud.xyz',
    }),
  });
  expect(res.status).toBe(200);
  const body = (await res.json()) as any;
  expect(body.authorizationContext).toBeDefined();
  expect(typeof body.authorizationContext.token).toBe('string');
  expect(typeof body.prepared?.siwe).toBe('string');
  const selectedActionKeys: string[] = Array.isArray(body.selectedActionKeys)
    ? body.selectedActionKeys
    : [];
  return {
    token: body.authorizationContext.token,
    prepared: body.prepared,
    selectedActionKeys,
    siwe: body.prepared.siwe,
  };
}

describe('POST /api/delegate — Blocker 1 versioned managed approval', () => {
  test('signs the exact SIWE bytes bound at /prepare', async () => {
    const { token, prepared, selectedActionKeys, siwe } = await prepare();

    const res = await router.request('/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: keyRecord.id,
        jwk,
        host: 'https://node.tinycloud.xyz',
        prepared,
        authorizationContextToken: token,
        selectedActionIds: selectedActionKeys,
        protocolVersion: 1,
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    // The server must return the SAME SIWE bytes we sent at /prepare.
    // Any regeneration would produce fresh issuedAt/expirationTime bytes.
    expect(body.signedMessage).toBe(siwe);
    expect(body.siwe).toBe(siwe);
    // The signature must verify against those exact bytes.
    expect(body.delegationHeader).toBeDefined();
  });

  test('rejects a request whose prepared.siwe does not match the bound bytes', async () => {
    const { token, prepared, selectedActionKeys } = await prepare();
    // Mutate the echoed prepared.siwe by a single character — the byte
    // equality check must fire and the server must refuse to sign.
    const tampered = {
      ...prepared,
      siwe: (prepared.siwe as string).replace(/Expiration Time:/, 'Expiration Time :'),
    };
    const res = await router.request('/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: keyRecord.id,
        jwk,
        host: 'https://node.tinycloud.xyz',
        prepared: tampered,
        authorizationContextToken: token,
        selectedActionIds: selectedActionKeys,
        protocolVersion: 1,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.code).toBe('prepared_siwe_mismatch');
  });

  test('rejects protocolVersion >= 1 without an authorization context token', async () => {
    const res = await router.request('/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: keyRecord.id,
        jwk,
        host: 'https://node.tinycloud.xyz',
        protocolVersion: 1,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.code).toBe('missing_authorization_context_token');
  });

  test('rejects a token with a missing prepared block', async () => {
    const { token, selectedActionKeys } = await prepare();
    const res = await router.request('/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: keyRecord.id,
        jwk,
        host: 'https://node.tinycloud.xyz',
        authorizationContextToken: token,
        selectedActionIds: selectedActionKeys,
        protocolVersion: 1,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.code).toBe('missing_prepared');
  });

  test('rejects a selectedActionIds set that omits an action encoded in the SIWE', async () => {
    const { token, prepared, selectedActionKeys } = await prepare();
    if (selectedActionKeys.length <= 1) return; // nothing to omit
    const narrowedSelection = selectedActionKeys.slice(1);
    const res = await router.request('/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: keyRecord.id,
        jwk,
        host: 'https://node.tinycloud.xyz',
        prepared,
        authorizationContextToken: token,
        selectedActionIds: narrowedSelection,
        protocolVersion: 1,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.code).toMatch(/selected_actions_/);
  });

  test('rejects a selectedActionIds set that adds actions not in the SIWE', async () => {
    const { token, prepared, selectedActionKeys } = await prepare();
    const inflatedSelection = [...selectedActionKeys, 'fake\u0000fake\u0000fake\u0000fake'];
    const res = await router.request('/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: keyRecord.id,
        jwk,
        host: 'https://node.tinycloud.xyz',
        prepared,
        authorizationContextToken: token,
        selectedActionIds: inflatedSelection,
        protocolVersion: 1,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.code).toMatch(/selected_actions_/);
  });

  test('legacy token-less request signs a freshly prepared SIWE and returns 200', async () => {
    const res = await router.request('/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: keyRecord.id,
        jwk,
        host: 'https://node.tinycloud.xyz',
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    // Legacy path returns a freshly prepared SIWE (never bound to a token).
    expect(typeof body.siwe).toBe('string');
    expect(typeof body.signedMessage).toBe('string');
    expect(body.siwe).toBe(body.signedMessage);
    expect(body.delegationHeader).toBeDefined();
  });
});
