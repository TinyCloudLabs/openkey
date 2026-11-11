// TC-2232 child: POST /api/keys/:id/sign hosts the signer's OWN space a TinyCloud sign-in names before it
// signs, so a brand-new account signing in to an app that asks only for `applications` does not make the
// SDK host the space itself (a "Create a new TinyCloud space" screen).
//
// These tests run the real keys route, the real TinyCloud bootstrap and the real WASM against a loopback
// node (fake-tinycloud-node.ts). Only the database, the TEE and the session middleware are stand-ins.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const other = '0x1111111111111111111111111111111111111111';
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED' as const,
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};
const spaceId = (name: string, owner: string = account.address) => `tinycloud:pkh:eip155:1:${owner}:${name}`;
const SPACES = ['default', 'applications', 'account', 'secrets', 'public', 'agents'];
const ORIGIN = 'https://app.example.test';

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

// What happened, in order: the node hosting a space, and the key signing.
let events: string[] = [];
// The message the test asked the key to sign: the bootstrap signs its own host delegations with the same key.
let appMessage = "";
const unseal = mock(async () => privateKey);

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
    seal: mock(async () => 'sealed-private-key'),
    unseal,
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return {
        address: wallet.address,
        signMessage: async (args: { message: string }) => {
          events.push(args.message === appMessage ? 'sign' : 'sign:host');
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
});

let keysRouter: { request: (path: string, init?: RequestInit) => Promise<Response> };
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
  // Imported after mock.module (and with an isolating query) so the route binds the mocked database and TEE.
  ({ keysRouter } = await import('../routes/keys?own-space-isolated' as string));
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
  events = [];
  logLines.length = 0;
  unseal.mockClear();
  prisma.user.findUnique.mockClear();
  prisma.tinyCloudBootstrapState.findUnique.mockClear();
  prisma.tinyCloudBootstrapState.create.mockClear();
  process.stdout.write = ((chunk: string | Uint8Array) => {
    for (const line of String(chunk).split('\n')) {
      if (line.startsWith('{')) logLines.push(JSON.parse(line));
    }
    return true;
  }) as typeof process.stdout.write;
  // The fake node reports each host delegation it applies; the order against the signature is what matters.
  node.beforeHost = async (id) => { events.push(`host:${id.slice(id.lastIndexOf(':') + 1)}`); };
});

afterEach(async () => {
  // The setup a request leaves running in the background must end before its node stops, or its
  // failure would be logged into the next test.
  await until(
    () => !state || state.status !== 'in_progress' || state.attemptId === 'someone-else',
    'the background setup to settle',
  );
  process.stdout.write = originalWrite;
  node.stop();
});

afterAll(() => {
  for (const name of ENV) {
    if (savedEnv[name] === undefined) delete process.env[name];
    else process.env[name] = savedEnv[name];
  }
});

/** The SDK's sign-in for `address` to one space: `abilities` are the service -> path -> actions in it. */
function siweFor(options: {
  space: string;
  address?: string;
  abilities?: Record<string, Record<string, string[]>>;
  expiresInMs?: number;
  domain?: string;
  rawAbilities?: Record<string, string[]>;
}) {
  return prepareSession({
    address: options.address ?? account.address,
    chainId: 1,
    domain: options.domain ?? 'app.example.test',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + (options.expiresInMs ?? 3_600_000)).toISOString(),
    spaceId: options.space,
    jwk,
    abilities: options.abilities ?? { kv: { 'data/': ['tinycloud.kv/get', 'tinycloud.kv/put'] } },
    ...(options.rawAbilities ? { rawAbilities: options.rawAbilities } : {}),
  } as never).siwe;
}

const applicationsOnly = () => siweFor({ space: spaceId('applications') });
const accountSignIn = () => siweFor({
  space: spaceId('account'),
  abilities: { capabilities: { capabilities: ['tinycloud.capabilities/read'] } },
});

interface SignBody {
  signature?: string;
  address?: string;
  tinycloudBootstrap?: { status: string; errorCode?: string };
}

async function sign(message: string, extra: Record<string, unknown> = {}) {
  appMessage = message;
  const response = await keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify({ message, requestOrigin: ORIGIN, ...extra }),
  });
  return { status: response.status, body: (await response.json()) as SignBody };
}

// Real clock on purpose: the node timeouts and the lock wait are AbortSignal.timeout and setTimeout
// against a real loopback server; fake timers would not move them.
async function until(condition: () => boolean, what: string, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(10);
  }
}

const hostPostsFor = (name: string) => node.hostPosts.filter((post) => post.spaceId === spaceId(name));
const errorLogs = () => logLines.filter((line) => line.level === 'error');

describe('a brand-new account signing in for `applications` only', () => {
  test('hosts the applications space before the reply, waits for nothing else, and signs after', async () => {
    // The node holds every other space's host delegation until released: the reply can only come
    // from the applications space alone.
    const others = Promise.withResolvers<void>();
    node.beforeHost = async (id) => {
      events.push(`host:${id.slice(id.lastIndexOf(':') + 1)}`);
      if (id !== spaceId('applications')) await others.promise;
    };
    try {
      const signed = await sign(applicationsOnly());

      expect(signed.status).toBe(200);
      expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
      expect(signed.body.address).toBe(account.address);
      expect(signed.body.tinycloudBootstrap).toEqual({ status: 'hosted' });
      expect([...node.hosted]).toEqual([spaceId('applications')]);
      expect(events.indexOf('host:applications')).toBeGreaterThanOrEqual(0);
      expect(events.indexOf('host:applications')).toBeLessThan(events.indexOf('sign'));
      expect(state?.status).toBe('in_progress');
    } finally {
      others.resolve();
    }

    // The rest of the setup continues in the background, and the hosted space is not hosted twice.
    await until(() => state?.status === 'complete', 'the background setup to complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map((name) => spaceId(name)).sort());
    expect(hostPostsFor('applications')).toHaveLength(1);
    expect(errorLogs()).toEqual([]);
  });

  test('a sign-in for the default space is handled the same way', async () => {
    const signed = await sign(siweFor({ space: spaceId('default') }));

    expect(signed.status).toBe(200);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'hosted' });
    expect(node.hosted.has(spaceId('default'))).toBe(true);
    expect(events.indexOf('host:default')).toBeLessThan(events.indexOf('sign'));
  });
});

describe('an account that is already set up', () => {
  test('adds no delay and makes no node call', async () => {
    state = { id: 'state_1', status: 'complete' };

    const start = performance.now();
    const signed = await sign(applicationsOnly());

    expect(performance.now() - start).toBeLessThan(250);
    expect(signed.status).toBe(200);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'complete' });
    expect(node.hostPosts).toEqual([]);
    expect(node.peerGets).toEqual([]);
    expect(events).toEqual(['sign']);
  });
});

describe('what is never a trigger', () => {
  test('another account\'s applications space, named in a sign-in by this signer', async () => {
    const signed = await sign(siweFor({ space: spaceId('applications', other) }));

    expect(signed.status).toBe(200);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'skipped' });
    expect(node.hostPosts).toEqual([]);
    expect(prisma.user.findUnique).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
    expect(events).toEqual(['sign']);
  });

  test('a sign-in by another address, even for a space that looks like this signer\'s', async () => {
    const signed = await sign(siweFor({ address: other, space: spaceId('applications') }));

    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'skipped' });
    expect(node.hostPosts).toEqual([]);
    expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
  });

  test('a space that is not a canonical bootstrap space', async () => {
    const signed = await sign(siweFor({ space: spaceId('messages') }));

    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'skipped' });
    expect(node.hostPosts).toEqual([]);
    expect(prisma.user.findUnique).not.toHaveBeenCalled();
  });

  test('a raw-format signature, whatever the bytes', async () => {
    const hex = `0x${Buffer.from(applicationsOnly()).toString('hex')}`;
    const signed = await sign(hex, { format: 'raw' });

    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'skipped' });
    expect(node.hostPosts).toEqual([]);
  });
});

describe('with Auto-Sign off', () => {
  test('nothing is hosted and the sign-in is unchanged', async () => {
    autoSignEnabled = false;

    const signed = await sign(applicationsOnly());

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'skipped' });
    expect(node.hostPosts).toEqual([]);
    expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
    expect(events).toEqual(['sign']);
  });

  test('the kill switch also leaves it unchanged', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';

    const signed = await sign(applicationsOnly());

    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'skipped' });
    expect(node.hostPosts).toEqual([]);
  });
});

describe('when hosting takes too long or cannot start', () => {
  test('a node slower than the bound replies pending with the signature, and the background hosts the space', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS = '60';
    node.beforeHost = async (id) => { if (id === spaceId('applications')) await Bun.sleep(500); };

    const start = performance.now();
    const signed = await sign(applicationsOnly());

    expect(performance.now() - start).toBeLessThan(450);
    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'pending' });
    expect(node.hosted.has(spaceId('applications'))).toBe(false);
    expect(errorLogs()).toEqual([]);

    await until(() => state?.status === 'complete', 'the background setup to complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map((name) => spaceId(name)).sort());
    expect(hostPostsFor('applications')).toHaveLength(1);
  });

  test('another run holding the lock is pending after the 500 ms wait, not an error, and nothing is hosted by this request', async () => {
    state = { id: 'state_1', status: 'in_progress', attemptId: 'someone-else', lockExpiresAt: new Date(Date.now() + 60_000) };

    const start = performance.now();
    const signed = await sign(applicationsOnly());
    const elapsed = performance.now() - start;

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'pending' });
    expect(elapsed).toBeGreaterThanOrEqual(450);
    expect(elapsed).toBeLessThan(2000);
    expect(node.hostPosts).toEqual([]);
    expect(errorLogs()).toEqual([]);
    expect(state?.attemptId).toBe('someone-else');
  });

  test('a node that refuses the host delegation still signs, reports the failure, and does not retry with the key', async () => {
    // A 1 ms retry delay: were the approval to keep the key and retry, a second host POST would show at once.
    process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = '1';
    node.hostStatus = 503;

    const signed = await sign(applicationsOnly());

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signed.body.tinycloudBootstrap?.status).toBe('failed');
    expect(signed.body.tinycloudBootstrap?.errorCode).toBeString();
    expect(errorLogs().map((line) => line.event)).toContain('tinycloud_bootstrap_failed');
    await Bun.sleep(300);
    expect(hostPostsFor('applications')).toHaveLength(1);
  });

  test('a sign-in that expires within seconds fails the same way the account setup does, and hosts nothing', async () => {
    const signed = await sign(siweFor({ space: spaceId('applications'), expiresInMs: 1_000 }));

    expect(signed.status).toBe(200);
    expect(signed.body.tinycloudBootstrap?.status).toBe('failed');
    expect(signed.body.tinycloudBootstrap?.errorCode).toBe('tinycloud_bootstrap_expired_request');
    expect(node.hostPosts).toEqual([]);
  });
});

describe('the account-space sign-in is unchanged', () => {
  test('it still runs the whole setup within the sync budget and is not treated as a requested space', async () => {
    node.beforeHost = async (id) => { events.push(`host:${id.slice(id.lastIndexOf(':') + 1)}`); };

    const signed = await sign(accountSignIn());

    expect(signed.status).toBe(200);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'complete' });
    expect(state?.status).toBe('complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map((name) => spaceId(name)).sort());
  });

});

describe('an account whose setup keeps failing', () => {
  const failedAgo = (ms: number): StateRow => ({
    id: 'state_1', status: 'failed', failureCode: 'tinycloud_bootstrap_host_failed', failureReason: 'node refused', checkedAt: new Date(Date.now() - ms),
  });

  test('a recent failure: the sign-in neither waits for nor re-claims the setup (the sweep retries it)', async () => {
    state = failedAgo(60_000);
    process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS = '5000';
    node.beforeHost = async (id) => { if (id === spaceId('applications')) await Bun.sleep(400); };

    const start = performance.now();
    const signed = await sign(applicationsOnly());

    expect(performance.now() - start).toBeLessThan(300);
    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'pending' });
    await Bun.sleep(100);
    expect(node.hostPosts).toEqual([]);
    expect(state?.status).toBe('failed');
    expect(state?.attemptId).toBeUndefined();
  });

  test('an old failure is waited for again', async () => {
    state = failedAgo(10 * 60_000);
    process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS = '5000';
    node.beforeHost = async (id) => { if (id === spaceId('applications')) await Bun.sleep(400); };

    const start = performance.now();
    const signed = await sign(applicationsOnly());

    expect(performance.now() - start).toBeGreaterThanOrEqual(350);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'hosted' });
    expect(node.hosted.has(spaceId('applications'))).toBe(true);
  });
});

// TC-2247 x TC-2285: the own-sites gate runs before the bootstrap, so a sign it refuses hosts nothing.
describe('a sign the own-sites gate refuses', () => {
  const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${account.address}:default`;
  const decryptOnNetwork = { [network]: ['tinycloud.encryption/decrypt'] };

  test('from a site that is not first-party: refused 403, nothing hosted, no setup state, nothing signed', async () => {
    const signed = await sign(siweFor({ space: spaceId('applications'), rawAbilities: decryptOnNetwork }));

    expect(signed.status).toBe(403);
    expect(signed.body).toMatchObject({ code: 'app_key_grant_refused' });
    expect(signed.body.signature).toBeUndefined();
    expect(node.hostPosts).toEqual([]);
    expect(node.peerGets).toEqual([]);
    expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
    expect(unseal).not.toHaveBeenCalled();
    expect(state).toBeNull();
  });

  test('the same message from a first-party site passes the gate and then hosts the signer\'s own space', async () => {
    const signed = await sign(
      siweFor({ space: spaceId('applications'), rawAbilities: decryptOnNetwork, domain: 'share.tinycloud.xyz' }),
      { requestOrigin: 'https://share.tinycloud.xyz' },
    );

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'hosted' });
    expect(hostPostsFor('applications')).toHaveLength(1);
  });
});
