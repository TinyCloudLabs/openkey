// The owner approves on OpenKey's own page: an approval request, a device request or a legacy link that returns to
// loopback or by paste. OpenKey sets the account up only from state it holds for the session's own user, read just
// before the setup and after the context was spent. Real delegate route, real bootstrap, real WASM and a loopback node;
// the database, the TEE, the session and the approval-request store are stand-ins.

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
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import('../routes/delegate?provision-authority-own-page' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import('../services/authorization-signing?provision-authority-own-page' as string));
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

function expectNoAccountSetUp() {
  expect(node.peerGets).toEqual([]);
  expect(node.hostPosts).toEqual([]);
  expect(node.hosted.size).toBe(0);
  expect(node.invokes).toBe(0);
  expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
  expect(prisma.tinyCloudBootstrapState.updateMany).not.toHaveBeenCalled();
  expect(state).toBeNull();
}

describe('a link that returns by paste or to loopback', () => {
  test('a paste link sets the account up and records the authority', async () => {
    const approved = await approve({ prepareExtra: { linkDelivery: 'paste' } });

    expect(approved.status).toBe(200);
    await until(() => state?.status === 'complete', 'the setup to complete');
    expectAccountSetUp('delegate-link-local');
  });

  test('a loopback callback link sets the account up', async () => {
    const approved = await approve({ prepareExtra: { linkDelivery: 'callback', linkCallback: 'http://127.0.0.1:43111/cb' } });

    expect(approved.status).toBe(200);
    await until(() => state?.status === 'complete', 'the setup to complete');
    expectAccountSetUp('delegate-link-local');
  });

  test('a link to another site is signed for and nothing is set up', async () => {
    const approved = await approve({ prepareExtra: { linkDelivery: 'callback', linkCallback: 'https://evil.example/cb' } });

    expect(approved.status).toBe(200);
    expect(approved.body.delegationHeader?.Authorization).toBeTruthy();
    expectNoAccountSetUp();
  });

  test('a lookalike of a loopback callback is signed for and nothing is set up', async () => {
    for (const callback of ['http://127.0.0.1.evil.com:43111/cb', 'http://127.0.0.1@evil.example', 'http://localhost.evil.com:1/x', 'http://2130706433:43111/cb']) {
      resetContexts?.();
      const approved = await approve({ prepareExtra: { linkDelivery: 'callback', linkCallback: callback } });
      expect(approved.status).toBe(200);
    }
    expectNoAccountSetUp();
  });

  test('a link that says nothing about how it returns is signed for and nothing is set up', async () => {
    const approved = await approve();

    expect(approved.status).toBe(200);
    expectNoAccountSetUp();
  });

  test('how the link returns is read at prepare time, never from the approval', async () => {
    const approved = await approve({ approveExtra: { linkDelivery: 'paste', linkCallback: 'http://127.0.0.1:43111/cb' } });

    expect(approved.status).toBe(200);
    expectNoAccountSetUp();
  });
});

describe('an approval request', () => {
  const REQUEST = { approvalRequestId: 'request_owner' };

  test('sets the account up and records the authority', async () => {
    const approved = await approve({ prepareExtra: REQUEST });

    expect(approved.status).toBe(200);
    await until(() => state?.status === 'complete', 'the setup to complete');
    expectAccountSetUp('approval-request');
    // Read before signing and again just before the setup.
    expect(checkApprovalDelegation.mock.calls.length).toBeGreaterThanOrEqual(3);
  });

  test('is signed for and not set up when the request was denied or expired after it was checked', async () => {
    // /prepare reads it, the check before signing reads it, then the read just before the setup refuses it.
    approvalChecks = [() => {}, () => {}, () => { throw new Error('Approval request is no longer pending'); }];

    const approved = await approve({ prepareExtra: REQUEST });

    expect(approved.status).toBe(200);
    expect(approved.body.delegationHeader?.Authorization).toBeTruthy();
    expectNoAccountSetUp();
  });

  test('is refused for a user other than the one the context was bound to, and sets nothing up', async () => {
    const approved = await approve({ prepareExtra: REQUEST, asUser: other });

    expect(approved.status).toBeGreaterThanOrEqual(400);
    expect(approved.body.delegationHeader).toBeUndefined();
    expectNoAccountSetUp();
  });

  test('the context is spent once: a replay signs nothing and sets nothing up', async () => {
    const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default', permissions: wholeSpace('default'), ...REQUEST });
    const body = {
      keyId: keyRecord.id,
      jwk,
      host: node.url,
      permissions: wholeSpace('default'),
      prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
      ...REQUEST,
    };
    expect((await post('/', body)).status).toBe(200);
    await until(() => state?.status === 'complete', 'the setup to complete');
    const hosted = node.hosted.size;
    const posts = node.hostPosts.length;

    const replay = await post('/', body);

    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(node.hosted.size).toBe(hosted);
    expect(node.hostPosts.length).toBe(posts);
  });
});

describe('a device request', () => {
  // A device names explicit paths, never a whole space.
  const devicePermissions = [
    { service: 'tinycloud.kv', space: 'default', path: 'notes/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
    { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] },
  ];
  let transactionId = '';

  beforeEach(async () => {
    const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
    const started = await deviceService.start({
      deviceSecretHash: digest(`secret-${Math.random()}`),
      codeChallenge: digest(`verifier-${Math.random()}`),
      sessionDid: sessionDidForPublicJwk(jwk),
      publicJwk: jwk,
      relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
      permissions: devicePermissions,
      nodeOrigin: node.url,
      shareOrigin: 'https://share.tinycloud.xyz',
      delegationTtlSeconds: 60,
    }, `198.51.100.${Math.floor(Math.random() * 250)}`);
    transactionId = started.transactionId;
  });

  test('sets the account up and records the authority', async () => {
    const approved = await approve({ prepareExtra: { deviceTransactionId: transactionId, expiry: '60s' }, permissions: devicePermissions });

    expect(approved.status).toBe(200);
    await until(() => state?.status === 'complete', 'the setup to complete');
    expectAccountSetUp('device-approval');
  });

  test('is signed for and not set up when the request is no longer pending just before the setup', async () => {
    const real = deviceService.assertDelegationWindow.bind(deviceService);
    const spy = spyOn(deviceService, 'assertDelegationWindow').mockImplementation(async (...args: Parameters<typeof real>) => {
      // Every read before the signature passes; the one after it (just before the setup) finds the request gone.
      if (unseal.mock.calls.length > 0) throw new DeviceAuthorizationError('expired_token', 'device authorization is no longer pending', 410);
      return real(...args);
    });
    try {
      const approved = await approve({ prepareExtra: { deviceTransactionId: transactionId, expiry: '60s' }, permissions: devicePermissions });

      expect(approved.status).toBe(200);
      expect(approved.body.delegationHeader?.Authorization).toBeTruthy();
      expectNoAccountSetUp();
    } finally {
      spy.mockRestore();
    }
  });

  test('is refused for a user other than the one the context was bound to, and sets nothing up', async () => {
    const approved = await approve({ prepareExtra: { deviceTransactionId: transactionId, expiry: '60s' }, permissions: devicePermissions, asUser: other });

    expect(approved.status).toBeGreaterThanOrEqual(400);
    expect(approved.body.delegationHeader).toBeUndefined();
    expectNoAccountSetUp();
  });

  test('the notice before approving follows the same switch the approval does', async () => {
    await expectNoticeFollowsSwitch('device-approval', { deviceTransactionId: transactionId, expiry: '60s' }, devicePermissions);
  });
});

/**
 * What /prepare tells the owner must be what approving then does. Turning one case off in `OWN_PAGE_APPROVAL_ENABLED`
 * must stop the notice promising a setup, not only stop the setup.
 */
async function expectNoticeFollowsSwitch(approval: keyof typeof OWN_PAGE_APPROVAL_ENABLED, prepareExtra: Record<string, unknown>, permissions: unknown) {
  const prepare = () => post('/prepare', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default', permissions, ...prepareExtra });
  const on = await prepare();
  expect(on.status).toBe(200);
  expect(on.body.spaceSetup).toEqual({ space: 'default', plan: 'setup' });

  const enabled = OWN_PAGE_APPROVAL_ENABLED as Record<string, boolean>;
  enabled[approval] = false;
  try {
    const off = await prepare();
    expect(off.status).toBe(200);
    expect(off.body.spaceSetup).toEqual({ space: 'default', plan: 'no-setup' });
    const approved = await approve({ prepareExtra, permissions });
    expect(approved.status).toBe(200);
    expectNoAccountSetUp();
  } finally {
    enabled[approval] = true;
  }
}

describe('the notice before approving', () => {
  test('for a paste link follows the same switch the approval does', async () => {
    await expectNoticeFollowsSwitch('delegate-link-local', { linkDelivery: 'paste' }, wholeSpace('default'));
  });

  test('for an approval request follows the same switch the approval does', async () => {
    await expectNoticeFollowsSwitch('approval-request', { approvalRequestId: 'request_owner' }, wholeSpace('default'));
  });

  test('for a link that returns anywhere else says approving does not set the account up', async () => {
    const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default', permissions: wholeSpace('default'), linkDelivery: 'callback', linkCallback: 'https://evil.example/cb' });
    expect(prepared.body.spaceSetup).toEqual({ space: 'default', plan: 'no-setup' });
  });
});

