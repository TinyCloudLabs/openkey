// TC-3441: refusals on /delegate routes carry a machine-readable `code`, and a
// wallet mismatch also names the wallet that owns the requested space. The
// `error` text of each reply is unchanged.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const other = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED' as 'MANAGED' | 'EXTERNAL',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};
let keyFound = true;

const prisma = {
  ethereumKey: {
    findFirst: mock(async () => (keyFound ? keyRecord : null)),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
const activateSessionWithHost = mock(async () => ({ success: true, status: 200, activated: [], skipped: [] }));

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
    createTeeClient: () => ({
      deriveKey: mock(async () => new Uint8Array(32)),
      getQuote: mock(async () => 'quote'),
      isInTee: () => false,
    }),
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrap: mock(async () => ({ status: 'complete' as const })),
    isTinyCloudBootstrapComplete: mock(async () => false),
  }),
  '../routes/approval-requests': () => ({
    admitApprovalDelegation: async () => {},
    checkApprovalDelegation: async () => {},
    bindApprovalRenewal: async () => undefined,
    confirmBoundRenewal: () => {},
    releaseApprovalDelegation: async () => {},
    saveApprovalDelegation: async (_body: unknown, _userId: string, delegation: Record<string, unknown>) => delegation,
  }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (with an isolating query) so the route binds the mocks above.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?refusal-codes-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?refusal-codes-routes-isolated' as string
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
  process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = 'off';
  resetContexts?.();
  keyFound = true;
  keyRecord.keyType = 'MANAGED';
  keyRecord.sealedBlob = 'sealed-blob';
  activateSessionWithHost.mockClear();
});

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function prepare(extra: Record<string, unknown> = {}) {
  const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host, ...extra });
  expect(prepared.status).toBe(200);
  return prepared.body;
}

async function completeBody(prepared: Record<string, any>) {
  const siwe = prepared.prepared.siwe as string;
  return {
    prepared: { ...prepared.prepared, siwe },
    signature: await account.signMessage({ message: siwe }),
    host,
    jwk,
    edited: false,
    protocolVersion: 1,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
  };
}

function managedBody(prepared: Record<string, any>, extra: Record<string, unknown>) {
  return {
    keyId: keyRecord.id,
    jwk,
    host,
    prepared: prepared.prepared,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
    protocolVersion: 1,
    ...extra,
  };
}

const ownSpace = `tinycloud:pkh:eip155:1:${account.address}:secrets`;
const otherSpace = `tinycloud:pkh:eip155:1:${other.address}:secrets`;
const kvGet = (space: string) => ({ service: 'tinycloud.kv', space, path: 'vault/secrets/TOKEN', actions: ['tinycloud.kv/get'] });
const secretsList = [{
  service: 'tinycloud.kv',
  space: 'secrets',
  path: 'vault/secrets/',
  actions: ['tinycloud.kv/list'],
  skipPrefix: true,
}];
const WALLET_MISMATCH = 'Requested spaces must belong to the signing account';
const SUBSET_REFUSAL = 'Edited permissions must be a subset of the original delegation request';

describe('POST /prepare', () => {
  test('a key that is gone answers 404 with the key_not_found code', async () => {
    keyFound = false;
    const res = await post('/prepare', { keyId: keyRecord.id, jwk, host });
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Key not found', code: 'key_not_found' });
  });

  test('a space owned by another wallet names that wallet', async () => {
    const res = await post('/prepare', { keyId: keyRecord.id, jwk, host, permissions: [kvGet(otherSpace)] });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(WALLET_MISMATCH);
    expect(res.body.code).toBe('invalid_permissions');
    expect(res.body.requestedSpaceOwner).toBe(other.address);
  });

  test('a space on another chain for the same wallet names no owner', async () => {
    const space = `tinycloud:pkh:eip155:5:${account.address}:secrets`;
    const res = await post('/prepare', { keyId: keyRecord.id, jwk, host, permissions: [kvGet(space)] });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(WALLET_MISMATCH);
    expect(res.body.code).toBe('invalid_permissions');
    expect(res.body).not.toHaveProperty('requestedSpaceOwner');
  });

  test('other permission refusals carry no owner', async () => {
    const res = await post('/prepare', {
      keyId: keyRecord.id, jwk, host, permissions: [{ ...kvGet(ownSpace), caveats: [{ maxSize: 1 }] }],
    });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('invalid_permissions');
    expect(res.body).not.toHaveProperty('requestedSpaceOwner');
  });
});

describe('POST /complete refusal on Approve', () => {
  test('a SIWE wider than the request keeps its error text and gains a code', async () => {
    const defaults = await prepare();
    const prepared = await prepare({ permissions: secretsList });
    const body = await completeBody(prepared);
    const wide = defaults.prepared.siwe as string;
    const refused = await post('/complete', {
      ...body,
      prepared: { ...body.prepared, siwe: wide },
      signature: await account.signMessage({ message: wide }),
      permissions: secretsList,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe(SUBSET_REFUSAL);
    expect(refused.body.code).toBe('invalid_permissions');
    expect(refused.body.message).toBe(SUBSET_REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('a space owned by another wallet names that wallet', async () => {
    const prepared = await prepare();
    const refused = await post('/complete', { ...(await completeBody(prepared)), permissions: [kvGet(otherSpace)] });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe(WALLET_MISMATCH);
    expect(refused.body.code).toBe('invalid_permissions');
    expect(refused.body.requestedSpaceOwner).toBe(other.address);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});

describe('POST / (managed approval) refusal on Approve', () => {
  test('a SIWE wider than the request keeps its error text and gains a code', async () => {
    const prepared = await prepare();
    const refused = await post('/', managedBody(prepared, { permissions: secretsList }));
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe(SUBSET_REFUSAL);
    expect(refused.body.code).toBe('invalid_permissions');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('a space owned by another wallet names that wallet', async () => {
    const prepared = await prepare();
    const refused = await post('/', managedBody(prepared, { permissions: [kvGet(otherSpace)] }));
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe(WALLET_MISMATCH);
    expect(refused.body.code).toBe('invalid_permissions');
    expect(refused.body.requestedSpaceOwner).toBe(other.address);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});
