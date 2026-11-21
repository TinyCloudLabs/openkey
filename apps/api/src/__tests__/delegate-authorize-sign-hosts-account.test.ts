// TC-3633: POST /api/delegate/authorize-sign (the versioned sign-in) hosts a managed account at the node, as
// POST /api/keys/:id/sign does. web-sdk 3.13 does not bootstrap an interactive signer itself, so a brand-new
// account that signed in here was never hosted and its first space operation failed.
//
// These tests run the real delegate route (prepare, preview, authorize-sign), the real TinyCloud bootstrap and
// the real WASM against a loopback node (fake-tinycloud-node.ts). Only the database, the TEE and the session
// middleware are stand-ins.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { verifyMessage } from 'ethers';
import { startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_hosts', email: 'hosts@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const keyRecord = {
  id: 'key_hosts',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED' as const,
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;
const SPACES = ['default', 'applications', 'account', 'secrets', 'public', 'agents'];

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
let autoSignEnabled = true;
const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled })) },
  tinyCloudBootstrapState: {
    findUnique: mock(async () => (state ? { ...state } : null)),
    create: mock(async ({ data }: { data: Omit<StateRow, 'id'> }) => {
      if (state) throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' });
      state = { ...data, id: 'state_1' };
      return state;
    }),
    updateMany: mock(async ({ where, data }: { where: Record<string, unknown>; data: Partial<StateRow> }) => {
      if (!state || (where.attemptId && where.attemptId !== state.attemptId)) return { count: 0 };
      // Lock acquisition (the only caller that sends an OR) only wins a free or expired lock.
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
      c.set('session', { id: 'session_hosts', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
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
    unseal,
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return { address: wallet.address, signMessage: async (input: { message: string }) => wallet.signMessage(input) };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];
let node: FakeTinyCloudNode;
const logLines: Array<{ event: string; level?: string; error_code?: string }> = [];
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
  ({ delegateRouter: router } = await import('../routes/delegate?hosts-account' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?hosts-account' as string
  ));
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
  autoSignEnabled = true;
  logLines.length = 0;
  unseal.mockClear();
  prisma.tinyCloudBootstrapState.create.mockClear();
  resetContexts?.();
  process.stdout.write = ((chunk: string | Uint8Array) => {
    for (const line of String(chunk).split('\n')) {
      if (line.startsWith('{')) logLines.push(JSON.parse(line));
    }
    return true;
  }) as typeof process.stdout.write;
});

afterEach(async () => {
  // The setup a request leaves running in the background must end before its node stops, or its
  // failure would be logged into the next test.
  await until(() => !state || state.status !== 'in_progress', 'the background setup to settle');
  process.stdout.write = originalWrite;
  node.stop();
});

afterAll(() => {
  for (const name of ENV) {
    if (savedEnv[name] === undefined) delete process.env[name];
    else process.env[name] = savedEnv[name];
  }
});

// Real clock on purpose: the node timeouts and the lock wait are AbortSignal.timeout and setTimeout
// against a real loopback server; fake timers would not move them.
async function until(condition: () => boolean, what: string, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(10);
  }
}

/** The sign-in the SDK prepares for `space` (the signer's own space, named by its ReCap). */
function siweFor(space: string) {
  const now = Date.now();
  return prepareSession({
    address: account.address,
    chainId: 1,
    domain: 'example.com',
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
async function signIn(siwe: string) {
  const prepared = await post('/authorize-sign-prepare', {
    keyId: keyRecord.id,
    siwe,
    jwk,
    host: 'https://node.tinycloud.xyz',
    requestOrigin: 'https://example.com',
  });
  expect(prepared.status).toBe(200);
  const previewed = await post('/authorize-sign-preview', {
    authorizationContextToken: prepared.body.authorizationContextToken,
    selectedActionIds: prepared.body.allowedActionIds,
  });
  expect(previewed.status).toBe(200);
  return {
    prepared: prepared.body,
    previewed: previewed.body,
    finalize: (selectedActionIds: string[] = prepared.body.allowedActionIds) => post('/authorize-sign', {
      authorizationContextToken: prepared.body.authorizationContextToken,
      previewApprovalToken: previewed.body.previewApprovalToken,
      selectedActionIds,
      protocolVersion: 1,
    }),
  };
}

const hostPostsFor = (name: string) => node.hostPosts.filter((post) => post.spaceId === spaceId(name));
const errorLogs = () => logLines.filter((line) => line.level === 'error');

describe('a brand-new managed account signing in for its own space', () => {
  test('is hosted before the signature is returned, and the rest of its setup completes', async () => {
    const siwe = siweFor(spaceId('applications'));
    const attempt = await signIn(siwe);

    const signed = await attempt.finalize();

    expect(signed.status).toBe(200);
    expect(signed.body.signedMessage).toBe(siwe);
    expect(verifyMessage(signed.body.signedMessage, signed.body.signature).toLowerCase())
      .toBe(account.address.toLowerCase());
    // The space the sign-in names is hosted by the time the reply is back: the SDK never has to host it.
    expect(node.hosted.has(spaceId('applications'))).toBe(true);

    await until(() => state?.status === 'complete', 'the background setup to complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map((name) => spaceId(name)).sort());
    expect(hostPostsFor('applications')).toHaveLength(1);
    expect(errorLogs()).toEqual([]);
  });

  test('a second sign-in hosts nothing again and does not unseal the key for the setup', async () => {
    const first = await signIn(siweFor(spaceId('applications')));
    expect((await first.finalize()).status).toBe(200);
    await until(() => state?.status === 'complete', 'the background setup to complete');
    const hostPosts = node.hostPosts.length;
    unseal.mockClear();

    const second = await signIn(siweFor(spaceId('applications')));
    expect((await second.finalize()).status).toBe(200);

    expect(node.hostPosts).toHaveLength(hostPosts);
    expect(prisma.tinyCloudBootstrapState.create).toHaveBeenCalledTimes(1);
    // The one unseal is the signature's own.
    expect(unseal).toHaveBeenCalledTimes(1);
  });
});

describe('what hosts nothing', () => {
  test('a sign that is refused', async () => {
    const attempt = await signIn(siweFor(spaceId('applications')));

    const refused = await attempt.finalize(['not-a-selected-action']);

    expect(refused.status).toBeGreaterThanOrEqual(400);
    expect(refused.body.signature).toBeUndefined();
    expect(node.hostPosts).toEqual([]);
    expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
  });

  test('Auto-Sign off: the sign-in is unchanged and nothing is hosted', async () => {
    autoSignEnabled = false;
    const attempt = await signIn(siweFor(spaceId('applications')));

    const signed = await attempt.finalize();

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(node.hostPosts).toEqual([]);
    expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
  });

  test('the kill switch', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';
    const attempt = await signIn(siweFor(spaceId('applications')));

    const signed = await attempt.finalize();

    expect(signed.status).toBe(200);
    expect(node.hostPosts).toEqual([]);
    expect(unseal).toHaveBeenCalledTimes(1);
  });

  test('a sign-in that names none of the signer\'s own spaces', async () => {
    const attempt = await signIn(siweFor(spaceId('messages')));

    const signed = await attempt.finalize();

    expect(signed.status).toBe(200);
    expect(node.hostPosts).toEqual([]);
    expect(unseal).toHaveBeenCalledTimes(1);
  });
});

describe('when the node cannot host the account', () => {
  test('the signature is still returned and the failure is logged', async () => {
    node.hostStatus = 503;
    const attempt = await signIn(siweFor(spaceId('applications')));

    const signed = await attempt.finalize();

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(node.hosted.has(spaceId('applications'))).toBe(false);
    expect(logLines.some((line) => line.event === 'tinycloud_bootstrap_failed')).toBe(true);
  });
});
