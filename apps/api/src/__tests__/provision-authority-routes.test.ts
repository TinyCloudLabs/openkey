// A sign-in only sets the account up on the node for a first-party authority. The versioned sign-in
// (`/authorize-sign-prepare` then `/authorize-sign`), the CLI approval (`/prepare` then `/`) and the
// host signer (`/host`) are run through the real delegate route, the real TinyCloud bootstrap and the real
// WASM against a loopback node (fake-tinycloud-node.ts). Only the database, the TEE and the session
// middleware are stand-ins.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, spyOn, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { verifyMessage } from 'ethers';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { FAKE_PEER_ID, startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_authority', email: 'authority@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const keyRecord = {
  id: 'key_authority',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED' as const,
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;
const SPACES = ['default', 'applications', 'account', 'secrets', 'public', 'agents'];
const FIRST_PARTY = 'https://home.tinycloud.xyz';
const THIRD_PARTY = 'https://example.com';

interface StateRow {
  id: string;
  status: string;
  attemptId?: string | null;
  lockExpiresAt?: Date | null;
  failureCode?: string | null;
  failureReason?: string | null;
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
      if (where.OR && state.status === 'in_progress' && state.lockExpiresAt && state.lockExpiresAt > new Date()) {
        return { count: 0 };
      }
      state = { ...state, ...data };
      return { count: 1 };
    }),
  },
};

const unseal = mock(async () => privateKey);

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_authority', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
  '../routes/device-authorization': () => ({ deviceAuthorizationService: {} }),
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
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;
let node: FakeTinyCloudNode;
let fetchSpy: ReturnType<typeof spyOn>;
const originalWrite = process.stdout.write;
const ENV = [
  'TINYCLOUD_BOOTSTRAP_HOST',
  'TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS',
  'TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS',
  'TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS',
  'TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS',
  'TINYCLOUD_BOOTSTRAP_ON_SIGN',
] as const;
const savedEnv = Object.fromEntries(ENV.map((name) => [name, process.env[name]]));

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?provision-authority-routes' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?provision-authority-routes' as string
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
  node = startFakeTinyCloudNode();
  process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
  process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = 'off';
  delete process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS;
  delete process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
  delete process.env.TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS;
  delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  state = null;
  unseal.mockClear();
  prisma.tinyCloudBootstrapState.create.mockClear();
  prisma.tinyCloudBootstrapState.findUnique.mockClear();
  prisma.tinyCloudBootstrapState.updateMany.mockClear();
  resetContexts?.();
  process.stdout.write = (() => true) as typeof process.stdout.write;
  fetchSpy = spyOn(globalThis, 'fetch');
});

afterEach(async () => {
  // The setup a request leaves running in the background must end before its node stops.
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

// Real clock on purpose: the node timeouts are AbortSignal.timeout against a real loopback server.
async function until(condition: () => boolean, what: string, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(10);
  }
}

/** The sign-in an app at `domain` prepares for `space`, the signer's own space. */
function siweFor(space: string, domain: string) {
  const now = Date.now();
  return prepareSession({
    address: account.address,
    chainId: 1,
    domain,
    issuedAt: new Date(now).toISOString(),
    expirationTime: new Date(now + 3_600_000).toISOString(),
    spaceId: space,
    jwk,
    abilities: { kv: { [space]: ['tinycloud.kv/get', 'tinycloud.kv/put'] } } as never,
  } as never).siwe as string;
}

async function post(path: string, body: Record<string, unknown>) {
  const response = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as any };
}

/** Prepare, preview and finalize an unchanged selection, as the approval screen does. */
async function signIn(domain: string, requestOrigin: string | undefined) {
  const prepared = await post('/authorize-sign-prepare', {
    keyId: keyRecord.id,
    siwe: siweFor(spaceId('applications'), domain),
    jwk,
    host: 'https://node.tinycloud.xyz',
    ...(requestOrigin === undefined ? {} : { requestOrigin }),
  });
  if (prepared.status !== 200) return { prepared, finalize: undefined };
  const previewed = await post('/authorize-sign-preview', {
    authorizationContextToken: prepared.body.authorizationContextToken,
    selectedActionIds: prepared.body.allowedActionIds,
  });
  expect(previewed.status).toBe(200);
  return {
    prepared,
    finalize: () => post('/authorize-sign', {
      authorizationContextToken: prepared.body.authorizationContextToken,
      previewApprovalToken: previewed.body.previewApprovalToken,
      selectedActionIds: prepared.body.allowedActionIds,
      protocolVersion: 1,
    }),
  };
}

function expectNothingSetUp() {
  expect(node.peerGets).toEqual([]);
  expect(node.hostPosts).toEqual([]);
  expect(node.sessionPosts).toEqual([]);
  expect(node.invokes).toBe(0);
  expect(fetchSpy).not.toHaveBeenCalled();
  expect(prisma.tinyCloudBootstrapState.findUnique).not.toHaveBeenCalled();
  expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
  expect(prisma.tinyCloudBootstrapState.updateMany).not.toHaveBeenCalled();
  expect(state).toBeNull();
}

describe('the versioned sign-in sets the account up only for a first-party app', () => {
  test('an app from another site is signed in and nothing is set up on the node', async () => {
    const attempt = await signIn('example.com', THIRD_PARTY);
    expect(attempt.prepared.status).toBe(200);

    const signed = await attempt.finalize!();

    expect(signed.status).toBe(200);
    expect(verifyMessage(signed.body.signedMessage, signed.body.signature).toLowerCase()).toBe(account.address.toLowerCase());
    expect(signed.body.signedMessage).toBeTruthy();
    expectNothingSetUp();
    // The one unseal is the signature's own.
    expect(unseal).toHaveBeenCalledTimes(1);
  });

  test('an app from another site gets the same response shape as a first-party app', async () => {
    const third = await (await signIn('example.com', THIRD_PARTY)).finalize!();
    const first = await (await signIn('home.tinycloud.xyz', FIRST_PARTY)).finalize!();

    expect(third.status).toBe(first.status);
    expect(Object.keys(third.body).sort()).toEqual(Object.keys(first.body).sort());
  });

  test('an app of TinyCloud is signed in and its account is hosted before the reply', async () => {
    const attempt = await signIn('home.tinycloud.xyz', FIRST_PARTY);

    const signed = await attempt.finalize!();

    expect(signed.status).toBe(200);
    expect(node.hosted.has(spaceId('applications'))).toBe(true);
    await until(() => state?.status === 'complete', 'the background setup to complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map((name) => spaceId(name)).sort());
  });

  test('TinyChat web is first-party', async () => {
    const attempt = await signIn('tinycloud.chat', 'https://tinycloud.chat');

    expect((await attempt.finalize!()).status).toBe(200);
    expect(node.hosted.has(spaceId('applications'))).toBe(true);
  });

  test('a request that names no origin is refused before anything is signed, and sets nothing up', async () => {
    const attempt = await signIn('home.tinycloud.xyz', undefined);

    expect(attempt.prepared.status).toBeGreaterThanOrEqual(400);
    expect(attempt.finalize).toBeUndefined();
    expectNothingSetUp();
  });

  test('a third-party app cannot pass as first-party by naming a first-party origin for its own SIWE', async () => {
    // The SIWE is the third party's; the origin field names TinyCloud's own app.
    const attempt = await signIn('example.com', FIRST_PARTY);

    expect(attempt.prepared.status).toBe(403);
    expect(attempt.finalize).toBeUndefined();
    expectNothingSetUp();
  });

  test('a third-party app cannot pass as first-party by writing a first-party domain in its origin spelling', async () => {
    for (const origin of [`${FIRST_PARTY}.evil.example`, `${FIRST_PARTY}/`, 'https://evil.example']) {
      const attempt = await signIn('home.tinycloud.xyz', origin);
      expect(attempt.prepared.status).toBeGreaterThanOrEqual(400);
    }
    expectNothingSetUp();
  });

  test('an app whose own origin and SIWE agree is judged by that origin, whatever else the request says', async () => {
    const prepared = await post('/authorize-sign-prepare', {
      keyId: keyRecord.id,
      siwe: siweFor(spaceId('applications'), 'example.com'),
      jwk,
      host: 'https://node.tinycloud.xyz',
      requestOrigin: THIRD_PARTY,
      reportedOrigin: FIRST_PARTY,
    });
    expect(prepared.status).toBe(200);
    const previewed = await post('/authorize-sign-preview', {
      authorizationContextToken: prepared.body.authorizationContextToken,
      selectedActionIds: prepared.body.allowedActionIds,
    });
    const signed = await post('/authorize-sign', {
      authorizationContextToken: prepared.body.authorizationContextToken,
      previewApprovalToken: previewed.body.previewApprovalToken,
      selectedActionIds: prepared.body.allowedActionIds,
      protocolVersion: 1,
    });
    expect(signed.status).toBe(200);
    expectNothingSetUp();
  });
});

describe('the approval of a command-line or device request sets nothing up', () => {
  const wholeSpace = (space: string) => [
    { service: 'tinycloud.kv', space, path: '', actions: ['tinycloud.kv/put', 'tinycloud.kv/get', 'tinycloud.kv/del', 'tinycloud.kv/list', 'tinycloud.kv/metadata'] },
    { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] },
  ];

  async function approveDefault() {
    const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default', permissions: wholeSpace('default') });
    expect(prepared.status).toBe(200);
    return post('/', {
      keyId: keyRecord.id,
      jwk,
      host: node.url,
      permissions: wholeSpace('default'),
      prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
    });
  }

  test('a new account approving a command-line request is signed for and not hosted', async () => {
    const approved = await approveDefault();

    expect(approved.status).toBe(200);
    expect(approved.body.delegationHeader?.Authorization).toBeTruthy();
    // The signed delegation is still registered with the node (the session activation); the account is not set up.
    expect(approved.body.hostActivated).toBe(true);
    expect(node.sessionPosts).toHaveLength(1);
    expect(approved.body.spaceReady).not.toBe(true);
    expect(node.peerGets).toEqual([]);
    expect(node.hostPosts).toEqual([]);
    expect(node.hosted.size).toBe(0);
    expect(node.invokes).toBe(0);
    expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.updateMany).not.toHaveBeenCalled();
    expect(state).toBeNull();
    // Only the delegation itself is signed with the managed key.
    expect(unseal).toHaveBeenCalledTimes(1);
  });
});

describe('the host signer', () => {
  test('signs nothing for any caller, and the node is not asked for a peer', async () => {
    const refused = await post('/host', { keyId: keyRecord.id, peerId: FAKE_PEER_ID, space: 'default' });

    expect(refused.status).toBe(403);
    expect(refused.body.code).toBe('host_signing_first_party_only');
    expect(refused.body.signature).toBeUndefined();
    expect(refused.body.siwe).toBeUndefined();
    expect(unseal).not.toHaveBeenCalled();
    expectNothingSetUp();
  });
});
