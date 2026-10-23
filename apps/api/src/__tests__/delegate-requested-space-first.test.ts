// TC-1608: a managed key's first TinyCloud approval hosts the space the client asked for before
// the response, and the rest of the setup (the other five spaces, the seeding) follows in the
// background under the same lock, with bounded node calls and a bounded retry.
//
// These tests run the real route, the real TinyCloud bootstrap and the real WASM signing
// against a loopback node (fake-tinycloud-node.ts). Only the database, the TEE and the session
// middleware are stand-ins.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { FAKE_PEER_ID, startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
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
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;
const SPACES = ['default', 'applications', 'account', 'secrets', 'public', 'agents'];

interface StateRow {
  id: string;
  status: string;
  attemptId?: string | null;
  lockExpiresAt?: Date | null;
  failureCode?: string | null;
  failureReason?: string | null;
}
let state: StateRow | null = null;
let history: StateRow[] = [];
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
      history.push({ ...state });
      return state;
    }),
    updateMany: mock(async ({ where, data }: { where: Record<string, unknown>; data: Partial<StateRow> }) => {
      if (!state || (where.attemptId && where.attemptId !== state.attemptId)) return { count: 0 };
      // Lock acquisition (the only caller that sends an OR) only wins a free or expired lock.
      if (where.OR && state.status === 'in_progress' && state.lockExpiresAt && state.lockExpiresAt > new Date()) {
        return { count: 0 };
      }
      state = { ...state, ...data };
      history.push({ ...state });
      return { count: 1 };
    }),
  },
};

// Every message the managed key signs, in order.
const signed: string[] = [];
const unseal = mock(async () => privateKey);

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
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
      return {
        address: wallet.address,
        signMessage: async (args: { message: string }) => {
          signed.push(args.message);
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;
let node: FakeTinyCloudNode;
interface LogLine {
  event: string;
  attempt?: number;
  error_code?: string;
  requested_space_hosted?: string;
  duration_ms?: number;
}
const logLines: LogLine[] = [];
const originalWrite = process.stdout.write;
const ENV = [
  'TINYCLOUD_BOOTSTRAP_HOST',
  'TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS',
  'TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS',
  'TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS',
] as const;
const savedEnv = Object.fromEntries(ENV.map((name) => [name, process.env[name]]));

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?requested-space-first-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?requested-space-first-isolated' as string
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
  delete process.env.TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS;
  resetContexts?.();
  state = null;
  history = [];
  signed.length = 0;
  logLines.length = 0;
  unseal.mockClear();
  process.stdout.write = ((chunk: string | Uint8Array) => {
    for (const line of String(chunk).split('\n')) {
      if (line.startsWith('{')) logLines.push(JSON.parse(line));
    }
    return true;
  }) as typeof process.stdout.write;
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

/** The fields of a route response these tests read. */
interface RouteBody {
  hostActivated?: boolean;
  spaceReady?: boolean | null;
  spacePending?: true;
  spaceError?: string;
  delegationHeader?: { Authorization: string };
  prepared?: unknown;
  authorizationContext?: { token: string };
  selectedActionKeys?: unknown;
}

async function post(path: string, body: Record<string, unknown>) {
  const response = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as RouteBody };
}

/** The first approval of a new account: the CLI asks for the `default` space. */
async function approveDefault() {
  const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default' });
  expect(prepared.status).toBe(200);
  return post('/', {
    keyId: keyRecord.id,
    jwk,
    host: node.url,
    prepared: prepared.body.prepared,
    authorizationContextToken: prepared.body.authorizationContext!.token,
    selectedActionIds: prepared.body.selectedActionKeys,
    protocolVersion: 1,
  });
}

// Real clock on purpose: the node timeouts and the retry delays under test are AbortSignal.timeout
// and setTimeout against a real loopback server; fake timers would not move them.
async function until(condition: () => boolean, what: string, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(10);
  }
}

const hostPostsFor = (name: string) => node.hostPosts.filter((post) => post.spaceId === spaceId(name));
const backgroundLogs = () => logLines.filter((line) => line.event.startsWith('tinycloud_bootstrap_background_'));

function deferred() {
  const { promise, resolve: release } = Promise.withResolvers<void>();
  return { promise, release };
}

describe('TC-1608 the requested space is hosted before the approval responds', () => {
  test('first approval returns spaceReady with the space hosted, without waiting for the other spaces', async () => {
    // The node holds every other space's host delegation until released: the response can only
    // come from the requested space alone.
    const others = deferred();
    node.beforeHost = async (id) => { if (id !== spaceId('default')) await others.promise; };
    try {
      const approved = await approveDefault();

      expect(approved.status).toBe(200);
      expect(approved.body).toMatchObject({ hostActivated: true, spaceReady: true, spaceId: spaceId('default') });
      expect(approved.body).not.toHaveProperty('spacePending');
      expect(approved.body).not.toHaveProperty('spaceError');
      expect([...node.hosted]).toEqual([spaceId('default')]);
      expect(node.hostPosts[0]!.spaceId).toBe(spaceId('default'));
      expect(state?.status).toBe('in_progress');
    } finally {
      others.release();
    }

    await until(() => state?.status === 'complete', 'the background setup to complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map(spaceId).sort());
    expect(backgroundLogs()).toEqual([
      expect.objectContaining({
        event: 'tinycloud_bootstrap_background_completed',
        attempt: 1,
        requested_space_hosted: 'yes',
        duration_ms: expect.any(Number),
      }),
    ]);
  });

  test('a node slower than the bound returns pending with a code, and the background hosts the space', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS = '50';
    node.beforeHost = async (id) => { if (id === spaceId('default')) await Bun.sleep(400); };

    const start = performance.now();
    const approved = await approveDefault();

    expect(performance.now() - start).toBeLessThan(380);
    expect(approved.status).toBe(200);
    expect(approved.body).toMatchObject({
      hostActivated: true,
      spaceReady: null,
      spacePending: true,
      spaceError: 'tinycloud_requested_space_timeout',
    });
    expect(node.hosted.has(spaceId('default'))).toBe(false);
    expect(approved.body.delegationHeader?.Authorization).toBeString();

    await until(() => state?.status === 'complete', 'the background setup to complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map(spaceId).sort());
    expect(hostPostsFor('default')).toHaveLength(1);
    expect(backgroundLogs()).toEqual([
      expect.objectContaining({
        event: 'tinycloud_bootstrap_background_completed',
        attempt: 1,
        requested_space_hosted: 'timeout',
      }),
    ]);
  });

  test('a node that refuses the host delegation keeps the client waiting while a retry is scheduled, then the retry hosts it', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = '150,150';
    node.hostStatus = 503;

    const approved = await approveDefault();

    // A failure that will be retried is not final: null + pending, with the reason.
    expect(approved.body).toMatchObject({ hostActivated: true, spaceReady: null, spacePending: true });
    expect(approved.body.spaceError).toContain('tinycloud_bootstrap_failed');
    expect(approved.body.spaceError).toContain('Failed to submit host delegation');
    expect(node.hosted.size).toBe(0);

    await until(() => backgroundLogs().length >= 1, 'the first failure to be logged');
    node.hostStatus = 200;
    await until(() => state?.status === 'complete', 'the retry to complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map(spaceId).sort());
    expect(backgroundLogs().map((line) => [line.event, line.attempt])).toEqual([
      ['tinycloud_bootstrap_background_failed', 1],
      ['tinycloud_bootstrap_background_completed', 2],
    ]);
  });

  test('the same failure is final when no retry will follow', async () => {
    node.hostStatus = 503; // retries are off in this file unless a test turns them on

    const approved = await approveDefault();

    expect(approved.body).toMatchObject({ hostActivated: true, spaceReady: false });
    expect(approved.body.spaceError).toContain('Failed to submit host delegation');
    expect(approved.body).not.toHaveProperty('spacePending');
  });

  // The node's answer to the host delegation is the confirmation: `activated` must list the space.
  // The session delegation the route already sent is a delegation the node holds, so re-sending it
  // answers `skipped: []` whether or not the space is hosted and would confirm nothing.
  test('a node that accepts the host delegation without activating the space is not reported ready', async () => {
    node.hostActivates = false;

    const approved = await approveDefault();

    expect(approved.body).toMatchObject({ hostActivated: true, spaceReady: false });
    expect(approved.body.spaceError).toContain('(tinycloud_bootstrap_space_not_hosted)');
    expect(node.hosted.size).toBe(0);
    await until(() => state?.status === 'failed', 'the failure to be recorded');
    expect(state).toMatchObject({ status: 'failed', failureCode: 'tinycloud_bootstrap_space_not_hosted' });
    // The route's own activation of the session delegation was answered, and re-sending a known
    // delegation gives the same empty `skipped`: nothing here can pass for confirmation.
    expect(node.sessionPosts).toHaveLength(1);
  });

  test('an unconfirmed space is retried and reported ready only once the node lists it', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = '150';
    node.hostActivates = false;

    const approved = await approveDefault();
    expect(approved.body).toMatchObject({ spaceReady: null, spacePending: true });
    expect(approved.body.spaceError).toContain('tinycloud_bootstrap_space_not_hosted');

    await until(() => backgroundLogs().length >= 1, 'the first failure to be logged');
    node.hostActivates = true;
    await until(() => state?.status === 'complete', 'the retry to complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map(spaceId).sort());
  });
});

describe('TC-1608 a failed background run recovers without another approval', () => {
  test('retries on its own, keeps the failure reason until it succeeds, and does not host the space twice', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = '80,80';
    node.invokeStatus = 500; // the schema and seeding fail after every space is hosted

    const approved = await approveDefault();
    expect(approved.body).toMatchObject({ spaceReady: true });

    await until(() => state?.status === 'failed', 'the first run to fail');
    expect(state).toMatchObject({ failureCode: 'tinycloud_bootstrap_failed' });
    expect(state?.failureReason).toContain('HTTP 500');
    const firstReason = state!.failureReason;

    node.invokeStatus = 200; // the node recovers
    await until(() => state?.status === 'complete', 'the retry to complete');

    // The retry took the lock from the failed state without wiping why it had failed.
    const retryStarted = history.find((row, index) => index > 0 && row.status === 'in_progress' && history[index - 1]!.status === 'failed');
    expect(retryStarted).toMatchObject({ failureCode: 'tinycloud_bootstrap_failed', failureReason: firstReason });
    // Success clears it.
    expect(state).toMatchObject({ failureCode: null, failureReason: null, attemptId: null, lockExpiresAt: null });

    expect(backgroundLogs().map((line) => [line.event, line.attempt, line.error_code ?? null])).toEqual([
      ['tinycloud_bootstrap_background_failed', 1, 'tinycloud_bootstrap_failed'],
      ['tinycloud_bootstrap_background_completed', 2, null],
    ]);
    // One approval, and the node-confirmed space was not signed or submitted again by the retry.
    expect(hostPostsFor('default')).toHaveLength(1);
  });

  test('stops after its bounded retries when the node stays down', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = '20,20,20';
    node.invokeStatus = 500;

    await approveDefault();
    await until(() => backgroundLogs().length === 4, 'the first run and three retries');
    await Bun.sleep(120);

    expect(backgroundLogs().map((line) => [line.event, line.attempt])).toEqual([
      ['tinycloud_bootstrap_background_failed', 1],
      ['tinycloud_bootstrap_background_failed', 2],
      ['tinycloud_bootstrap_background_failed', 3],
      ['tinycloud_bootstrap_background_failed', 4],
    ]);
    expect(state).toMatchObject({ status: 'failed', failureCode: 'tinycloud_bootstrap_failed' });
    expect(unseal).toHaveBeenCalledTimes(1 + 4); // the approval's own signature, then one per run
  });
});

describe('TC-1608 the sync path and the background never submit a conflicting host delegation', () => {
  test('every space receives exactly one host delegation across the sync path and the background run', async () => {
    const approved = await approveDefault();
    expect(approved.body.spaceReady).toBe(true);
    await until(() => state?.status === 'complete', 'the background setup to complete');

    for (const name of SPACES) expect(hostPostsFor(name)).toHaveLength(1);
    expect(node.peerGets.sort()).toEqual(SPACES.map(spaceId).sort());
  });

  test('an approval that arrives while the first one is still hosting waits on the lock instead of hosting again', async () => {
    const hold = deferred();
    node.beforeHost = async (id) => { if (id === spaceId('default')) await hold.promise; };
    const first = approveDefault();
    await until(() => hostPostsFor('default').length === 1, 'the first approval to submit its host delegation');

    const second = await approveDefault();

    expect(second.body).toMatchObject({
      hostActivated: true, spaceReady: null, spacePending: true, spaceError: 'tinycloud_bootstrap_in_progress',
    });
    expect(hostPostsFor('default')).toHaveLength(1);

    hold.release();
    expect((await first).body.spaceReady).toBe(true);
    await until(() => state?.status === 'complete', 'the background setup to complete');
    for (const name of SPACES) expect(hostPostsFor(name)).toHaveLength(1);
  });
});

// The managed key signs the same messages as before, in a different order: the requested
// space's host SIWE moves from the six-way batch to the front of the run.
describe('TC-1608 what the managed key signs', () => {
  const isHostSiwe = (message: string) => message.includes("'tinycloud.space': 'host'");
  const recapOf = (siwe: string) => {
    const recap = /urn:recap:([A-Za-z0-9_-]+)/.exec(siwe)![1]!;
    return JSON.parse(Buffer.from(recap, 'base64url').toString('utf8')).att as Record<string, Record<string, unknown>>;
  };
  const withoutNonce = (siwe: string) => siwe.replace(/^Nonce: .*\n/m, '').replace(/^Issued At: .*\n/m, '');

  test('signs only the existing host SIWE for the requested space, exactly once, and the same total as before', async () => {
    const approved = await approveDefault();
    expect(approved.body.spaceReady).toBe(true);
    await until(() => state?.status === 'complete', 'the background setup to complete');

    const hostSiwes = signed.filter(isHostSiwe);
    // Six host SIWEs, one per space, none repeated.
    expect(hostSiwes).toHaveLength(6);
    const defaultHost = hostSiwes.filter((siwe) => siwe.includes(`${spaceId('default')}/space`));
    expect(defaultHost).toHaveLength(1);

    // Unchanged shape: the statement and resources are what generateHostSIWEMessage produces,
    // and the recap grants `tinycloud.space/host` on that one space and nothing else.
    for (const name of SPACES) {
      const siwe = hostSiwes.find((candidate) => candidate.includes(`${spaceId(name)}/space`))!;
      const expected = generateHostSIWEMessage({
        address: account.address,
        chainId: 1,
        domain: 'cli.tinycloud.xyz',
        issuedAt: new Date().toISOString(),
        spaceId: spaceId(name),
        peerId: FAKE_PEER_ID,
      });
      expect(withoutNonce(siwe)).toBe(withoutNonce(expected));
      expect(recapOf(siwe)).toEqual({ [`${spaceId(name)}/space`]: { 'tinycloud.space/host': [{}] } });
    }
    // The requested space's host SIWE is signed first among the host SIWEs.
    expect(signed.findIndex(isHostSiwe)).toBe(signed.indexOf(defaultHost[0]!));

    // Before and after: the delegation itself (1), the account probe session (1) and six bootstrap
    // sessions, plus six host SIWEs: 14 signatures, none of them for a new ability.
    expect(signed).toHaveLength(14);
    expect(signed.filter((message) => !isHostSiwe(message))).toHaveLength(8);
  });
});

describe('TC-1608 a hung node call is aborted and releases the lock', () => {
  test('the call times out, the run fails with its reason, and the next approval takes the lock', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS = '100';
    node.beforePeer = () => new Promise<void>(() => {}); // the node never answers

    const start = performance.now();
    const approved = await approveDefault();

    // Aborted by its own timeout, well inside the 10 s the approval is willing to wait.
    expect(performance.now() - start).toBeLessThan(2000);
    expect(approved.body).toMatchObject({ hostActivated: true, spaceReady: false });
    expect(approved.body.spaceError).toContain('tinycloud_bootstrap_node_timeout');
    expect(approved.body.spaceError).toContain('timed out after 100 ms');
    // The lock is released, not held until its TTL: `failed` with no expiry.
    await until(() => backgroundLogs().length === 1, 'the failure to be logged');
    expect(state).toMatchObject({
      status: 'failed',
      failureCode: 'tinycloud_bootstrap_node_timeout',
      lockExpiresAt: null,
    });
    expect(state?.failureReason).toContain('timed out after 100 ms');
    expect(backgroundLogs()).toEqual([
      expect.objectContaining({ event: 'tinycloud_bootstrap_background_failed', error_code: 'tinycloud_bootstrap_node_timeout' }),
    ]);

    node.beforePeer = undefined;
    const next = await approveDefault();
    expect(next.body.spaceReady).toBe(true);
    await until(() => state?.status === 'complete', 'the next run to complete');
    expect([...node.hosted].sort()).toEqual(SPACES.map(spaceId).sort());
  });

  test("the route's own session activation is bounded too: a hung node does not hold the signed delegation back", async () => {
    process.env.TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS = '100';
    node.beforeSession = () => new Promise<void>(() => {}); // the node never answers the activation

    const start = performance.now();
    const approved = await approveDefault();

    expect(performance.now() - start).toBeLessThan(2000);
    expect(approved.status).toBe(200);
    // The client still gets the delegation; it is told the node did not activate it, and no setup ran.
    expect(approved.body.delegationHeader?.Authorization).toBeString();
    expect(approved.body).toMatchObject({ hostActivated: false, spaceReady: null });
    expect(state).toBeNull();
  });
});
