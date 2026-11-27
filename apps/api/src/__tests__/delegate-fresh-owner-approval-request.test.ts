// The Courier smoke: `courier init --request` posts a signed approval request; the owner, a fresh managed account with
// no TinyCloud space and Auto-Sign on, opens OpenKey's own approval page and approves once, which posts to /api/delegate.
// That one request must set the whole account up, the `agents` space first, from the `approval-request` authority, and
// answer with `spaceReady`. Real delegate route, real bootstrap, real WASM and a loopback node; the database, the TEE,
// the session and the approval-request store are stand-ins.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, spyOn, test } from 'bun:test';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { DeviceAuthorizationError, DeviceAuthorizationService, MemoryDeviceAuthorizationStore, sessionDidForPublicJwk } from '../services/device-authorization';
import { OWN_PAGE_APPROVAL_ENABLED } from '../services/provision-authority';
import { startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const owner = { id: 'user_owner', email: 'owner@example.test' };
const other = { id: 'user_other', email: 'other@example.test' };
let current = owner;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const keyRecord = {
  id: 'key_owner',
  userId: owner.id,
  address: account.address,
  keyType: 'MANAGED' as const,
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

interface StateRow {
  id: string;
  status: string;
  authority?: string | null;
  attemptId?: string | null;
  lockExpiresAt?: Date | null;
  failureCode?: string | null;
  checkedAt?: Date;
}
let state: StateRow | null = null;
const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {
    findUnique: mock(async () => (state ? { ...state } : null)),
    create: mock(async ({ data }: { data: Omit<StateRow, 'id'> }) => {
      if (state) throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' });
      state = { ...data, id: 'state_1' };
      return state;
    }),
    updateMany: mock(async ({ where, data }: { where: Record<string, unknown>; data: Partial<StateRow> }) => {
      if (!state || (where.attemptId && where.attemptId !== state.attemptId)) return { count: 0 };
      if (where.OR && state.status === 'in_progress' && state.lockExpiresAt && state.lockExpiresAt > new Date()) return { count: 0 };
      state = { ...state, ...data };
      return { count: 1 };
    }),
  },
};

const unseal = mock(async () => privateKey);
// The approval-request store: `checkApprovalDelegation` is what the route reads the request through. The first call is
// the check before signing; any later call is the read right before the account is set up.
let approvalChecks: Array<() => void> = [];
const checkApprovalDelegation = mock(async () => {
  const next = approvalChecks.shift();
  next?.();
});
const deviceService = new DeviceAuthorizationService(new MemoryDeviceAuthorizationStore(), {
  verificationOrigin: 'https://openkey.so',
  encryptionSecret: 'test-device-authorization-secret-is-long-enough',
});

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', current);
      c.set('session', { id: 'session_own_page', userId: current.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
  '../routes/device-authorization': () => ({ deviceAuthorizationService: deviceService }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({
      deriveKey: mock(async () => new Uint8Array(32)),
      getQuote: mock(async () => 'quote'),
      isInTee: () => false,
    }),
    unseal,
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return { address: wallet.address, signMessage: async (input: { message: string }) => wallet.signMessage(input) };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '../routes/approval-requests': () => ({
    admitApprovalDelegation: async () => {},
    checkApprovalDelegation,
    bindApprovalRenewal: async () => undefined,
    confirmBoundRenewal: () => {},
    releaseApprovalDelegation: async () => {},
    saveApprovalDelegation: async (_body: unknown, _userId: string, delegation: Record<string, unknown>) => delegation,
  }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;
let node: FakeTinyCloudNode;
let fetchSpy: ReturnType<typeof spyOn>;
const originalWrite = process.stdout.write;
const ENV = ['TINYCLOUD_BOOTSTRAP_HOST', 'TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS', 'TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS', 'TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS', 'TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS', 'TINYCLOUD_BOOTSTRAP_ON_SIGN'] as const;
const savedEnv = Object.fromEntries(ENV.map((name) => [name, process.env[name]]));

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import('../routes/delegate?fresh-owner-approval-request' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import('../services/authorization-signing?fresh-owner-approval-request' as string));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', current);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: current.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

beforeEach(() => {
  node = startFakeTinyCloudNode();
  current = owner;
  approvalChecks = [];
  process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
  process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = 'off';
  delete process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS;
  delete process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
  delete process.env.TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS;
  delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  state = null;
  unseal.mockClear();
  checkApprovalDelegation.mockClear();
  prisma.tinyCloudBootstrapState.create.mockClear();
  prisma.tinyCloudBootstrapState.findUnique.mockClear();
  prisma.tinyCloudBootstrapState.updateMany.mockClear();
  resetContexts?.();
  process.stdout.write = (() => true) as typeof process.stdout.write;
  fetchSpy = spyOn(globalThis, 'fetch');
});

afterEach(async () => {
  await until(() => !state || state.status !== 'in_progress', 'the background setup to settle');
  process.stdout.write = originalWrite;
  fetchSpy.mockRestore();
  node.stop();
});

afterAll(() => {
  for (const name of ENV) {
    if (savedEnv[name] === undefined) delete process.env[name];
    else process.env[name] = savedEnv[name];
  }
});

async function until(condition: () => boolean, what: string, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(10);
  }
}

async function post(path: string, body: Record<string, unknown>) {
  const response = await router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: response.status, body: (await response.json()) as any };
}

const wholeSpace = (space: string) => [
  { service: 'tinycloud.kv', space, path: '', actions: ['tinycloud.kv/put', 'tinycloud.kv/get', 'tinycloud.kv/del', 'tinycloud.kv/list', 'tinycloud.kv/metadata'] },
  { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] },
];

/** What the approval page sends to /prepare and then to /, for the extra fields `prepareExtra` and `approveExtra`. */
async function approve(opts: { prepareExtra?: Record<string, unknown>; approveExtra?: Record<string, unknown>; permissions?: unknown; asUser?: typeof owner } = {}) {
  const permissions = opts.permissions ?? wholeSpace('default');
  const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default', permissions, ...opts.prepareExtra });
  expect(prepared.status).toBe(200);
  if (opts.asUser) current = opts.asUser;
  return post('/', {
    keyId: keyRecord.id,
    jwk,
    host: node.url,
    permissions,
    prepared: prepared.body.prepared,
    authorizationContextToken: prepared.body.authorizationContext.token,
    selectedActionIds: prepared.body.selectedActionKeys,
    protocolVersion: 1,
    ...opts.prepareExtra,
    ...opts.approveExtra,
  });
}

function expectAccountSetUp(authority: string) {
  expect(node.hosted.size).toBeGreaterThan(0);
  expect(state?.authority).toBe(authority);
}

// A requested space outside `default` is looked up on the node when the approval is prepared; nothing is hosted or recorded.
function expectNoAccountSetUp() {
  expect(node.hostPosts).toEqual([]);
  expect(node.hosted.size).toBe(0);
  expect(node.invokes).toBe(0);
  expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
  expect(prisma.tinyCloudBootstrapState.updateMany).not.toHaveBeenCalled();
  expect(state).toBeNull();
}


const agentsPermissions = [
  { service: 'tinycloud.kv', space: 'agents', path: 'courier/', actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/list'] },
  { service: 'tinycloud.capabilities', space: 'agents', path: '', actions: ['tinycloud.capabilities/read'] },
];
const REQUEST = { approvalRequestId: 'request_courier' };
const spaceName = (id: string) => id.slice(id.lastIndexOf(':') + 1);

describe('a fresh owner approving an approval request on the OpenKey page', () => {
  test('sets the whole account up from the approval-request authority, the agents space first, and says spaceReady', async () => {
    const approved = await approve({ prepareExtra: REQUEST, permissions: agentsPermissions });

    expect(approved.status).toBe(200);
    expect(approved.body.spaceReady).toBe(true);
    expect(approved.body.spaceError).toBeUndefined();
    await until(() => state?.status === 'complete', 'the setup to complete');
    expect(state?.authority).toBe('approval-request');
    expect([...node.hosted].map(spaceName).sort()).toEqual(['account', 'agents', 'applications', 'default', 'public', 'secrets']);
    expect(spaceName(node.hostPosts[0]!.spaceId)).toBe('agents');
  });

  test('a request that is not the one bound at /prepare is signed for and sets nothing up', async () => {
    const approved = await approve({ prepareExtra: REQUEST, approveExtra: { approvalRequestId: 'request_forged' }, permissions: agentsPermissions });

    expect(approved.status).toBeGreaterThanOrEqual(200);
    expectNoAccountSetUp();
  });

  test('a request denied or expired after it was checked is signed for and sets nothing up', async () => {
    // /prepare reads it, the check before signing reads it, then the read that decides the authority refuses it.
    approvalChecks = [() => {}, () => {}, () => { throw new Error('Approval request is no longer pending'); }];

    const approved = await approve({ prepareExtra: REQUEST, permissions: agentsPermissions });

    expect(approved.status).toBe(200);
    expectNoAccountSetUp();
  });

  test('a different signed-in user cannot approve the context, and sets nothing up', async () => {
    const approved = await approve({ prepareExtra: REQUEST, permissions: agentsPermissions, asUser: other });

    expect(approved.status).toBeGreaterThanOrEqual(400);
    expect(approved.body.delegationHeader).toBeUndefined();
    expectNoAccountSetUp();
  });
});
