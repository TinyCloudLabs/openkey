// What /prepare tells the owner about their TinyCloud space: `spaceSetup` is the setup notice, present only when approving
// sets a space up. It is null for a reviewer account and for an account whose space already exists. Real delegate route
// and real WASM with a loopback node; the database, the TEE, the session and the approval-request store are stand-ins.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { reviewerSessionDid } from '../services/reviewer-delegation';
import { startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const owner = { id: 'user_owner', email: 'owner@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const keyRecord = {
  id: 'key_owner',
  userId: owner.id,
  address: account.address,
  keyType: 'MANAGED' as const,
  archivedAt: null,
  isCanonicalTinyCloud: true,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

let state: { id: string; status: string } | null = null;
let reviewer: { userId: string } | null = null;
const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  reviewerAccount: { findUnique: mock(async () => reviewer), findMany: mock(async () => []) },
  tinyCloudBootstrapState: { findUnique: mock(async () => (state ? { ...state } : null)) },
};

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', owner);
      c.set('session', { id: 'session_space_known', userId: owner.id, expiresAt: new Date(Date.now() + 60_000) });
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
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return { address: wallet.address, signMessage: async (input: { message: string }) => wallet.signMessage(input) };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '../routes/approval-requests': () => ({
    admitApprovalDelegation: async () => {},
    checkApprovalDelegation: async () => {},
    bindApprovalRenewal: async () => undefined,
    confirmBoundRenewal: () => {},
    releaseApprovalDelegation: async () => {},
    saveApprovalDelegation: async (_body: unknown, _userId: string, delegation: Record<string, unknown>) => delegation,
  }),
  // The reviewer's delegate is the one the reviewer guard in the delegate route checks the request against.
  '../services/reviewer-delegation': () => ({
    currentReviewerDelegate: async () => reviewer && {
      ...reviewer, keyId: keyRecord.id, nodeHost: node.url, sessionDid: reviewerSessionDid(jwk),
    },
    assertReviewerSignedDelegation: async () => {},
  }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;
let node: FakeTinyCloudNode;
const originalWrite = process.stdout.write;
const ENV = ['TINYCLOUD_BOOTSTRAP_HOST', 'TINYCLOUD_BOOTSTRAP_ON_SIGN'] as const;
const savedEnv = Object.fromEntries(ENV.map((name) => [name, process.env[name]]));

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import('../routes/delegate?delegate-prepare-space-known' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import('../services/authorization-signing?delegate-prepare-space-known' as string));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', owner);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: owner.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

beforeEach(() => {
  node = startFakeTinyCloudNode();
  state = null;
  reviewer = null;
  process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
  delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  resetContexts?.();
  process.stdout.write = (() => true) as typeof process.stdout.write;
});

afterEach(() => {
  process.stdout.write = originalWrite;
  node.stop();
});

afterAll(() => {
  for (const name of ENV) {
    if (savedEnv[name] === undefined) delete process.env[name];
    else process.env[name] = savedEnv[name];
  }
});

const wholeSpace = (space: string) => [
  { service: 'tinycloud.kv', space, path: '', actions: ['tinycloud.kv/put', 'tinycloud.kv/get', 'tinycloud.kv/del', 'tinycloud.kv/list', 'tinycloud.kv/metadata'] },
  { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] },
];

/** Mounted where the route lives in the API: the reviewer guard compares the full request path. */
async function prepare(extra: Record<string, unknown>, prefix = 'default') {
  const app = new Hono().route('/api/delegate', router);
  const response = await app.request('/api/delegate/prepare', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ keyId: keyRecord.id, jwk, host: node.url, prefix, permissions: wholeSpace(prefix), ...extra }),
  });
  return { status: response.status, body: (await response.json()) as any };
}

const REQUEST = { approvalRequestId: 'request_owner' };

describe('the space notice in the prepare reply', () => {
  test('is the setup notice for an approval request when the account has no complete bootstrap', async () => {
    const prepared = await prepare(REQUEST);

    expect(prepared.status).toBe(200);
    expect(prepared.body.spaceSetup).toEqual({ space: 'default', plan: 'setup' });
  });

  test('is null for an approval request when the account bootstrap is complete', async () => {
    state = { id: 'state_1', status: 'complete' };

    const prepared = await prepare(REQUEST);

    expect(prepared.status).toBe(200);
    expect(prepared.body.spaceSetup).toBeNull();
  });

  test('is null for a reviewer account', async () => {
    reviewer = { userId: owner.id };

    const prepared = await prepare({}, 'applications');

    expect(prepared.status).toBe(200);
    expect(prepared.body.spaceSetup).toBeNull();
  });
});
