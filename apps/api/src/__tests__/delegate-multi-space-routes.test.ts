import { afterAll, afterEach, beforeAll, beforeEach, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { makeSpaceId } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import { startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { parsePreparedRecap } from '../routes/delegate-session';
import type { delegateRouter } from '../routes/delegate';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'tc2490-owner', email: 'owner@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const key = { id: 'tc2490-key', userId: user.id, address: account.address, keyType: 'MANAGED', sealedBlob: 'fixture', archivedAt: null, sealingContext: null };
const permissions = [
  { service: 'tinycloud.kv', space: 'account', path: 'spaces/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
  { service: 'tinycloud.sql', space: 'applications', path: 'xyz.tinycloud.tinychat/home_feed', actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  ...['account', 'applications'].map(space => ({ service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] })),
];
const spaces = ['account', 'applications'].map(space => ({ space, spaceId: makeSpaceId(account.address, 1, space) }));
interface StateRow {
  id: string;
  status: string;
  attemptId?: string;
  lockExpiresAt?: Date;
}
interface RouteBody {
  spaceId: string;
  spaceReady: boolean | null;
  requestedSpaces: { space: string; spaceId: string; spaceReady: boolean | null; spacePending?: true; spaceError?: string }[];
  prepared: { siwe: string };
  authorizationContext: { token: string };
  selectedActionKeys: string[];
  siwe: string;
}
let state: StateRow | null = null;
let bootstrapSettled: Promise<void>;
let settleBootstrap!: () => void;
let autoSignEnabled = true;
const prisma = {
  appSignInDay: { upsert: mock(async () => ({})), deleteMany: mock(async () => ({})) },
  ethereumKey: { findFirst: mock(async () => key), findMany: mock(async () => [key]) },
  user: { findUnique: mock(async () => ({ autoSignEnabled })) },
  tinyCloudBootstrapState: {
    findUnique: mock(async () => state && { ...state }),
    create: mock(async ({ data }: { data: Omit<StateRow, 'id'> }) => {
      if (state) throw Object.assign(new Error('existing'), { code: 'P2002' });
      state = { ...data, id: 'tc2490-state' };
      return state;
    }),
    updateMany: mock(async ({ where, data }: { where: { attemptId?: string; OR?: unknown }; data: Partial<StateRow> }) => {
      if (!state || (where.attemptId && where.attemptId !== state.attemptId)) return { count: 0 };
      if (where.OR && state.status === 'in_progress' && state.lockExpiresAt && state.lockExpiresAt > new Date()) return { count: 0 };
      state = { ...state, ...data };
      if (state.status === 'complete' || state.status === 'failed') settleBootstrap();
      return { count: 1 };
    }),
  },
};
replaceModules({
  '../middleware/session': () => ({ requireSession: createMiddleware(async (c, next) => { c.set('user', user); await next(); }) }),
  '../routes/device-authorization': () => ({ deviceAuthorizationService: {} }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ isInTee: () => false, deriveKey: async () => new Uint8Array(32), getQuote: async () => 'fixture' }), unseal: async () => privateKey,
    createWalletFromPrivateKey: (value: `0x${string}`) => privateKeyToAccount(value),
    generatePrivateKey: () => privateKey, getAddressFromPrivateKey: () => account.address,
  }),
});
let router: typeof delegateRouter;
let node: FakeTinyCloudNode;
const savedEnv = Object.fromEntries(['TINYCLOUD_BOOTSTRAP_HOST', 'TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS', 'TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS'].map(name => [name, process.env[name]]));
beforeAll(async () => {
  // The route captures Prisma at module load; import after the isolated mocks bind it.
  const route = await import('../routes/delegate?tc2490-multi-space-routes' as string);
  router = route.delegateRouter;
  route.setDelegateSignerAuthMiddlewareForTests(createMiddleware(async (c, next) => {
    c.set('user', user); c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null); c.set('delegateSignerAuthFailure', null); await next();
  }));
});
beforeEach(() => {
  node = startFakeTinyCloudNode(); state = null; autoSignEnabled = true;
  bootstrapSettled = new Promise<void>(resolve => { settleBootstrap = resolve; });
  process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
  process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = 'off';
  process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS = '100';
});
afterEach(async () => {
  // Drain the real bootstrap's background seeding before closing its loopback node.
  if (state?.status === 'in_progress') await bootstrapSettled;
  node.stop();
});
afterAll(() => {
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});
async function post(path: string, body: Record<string, unknown>) {
  const response = await router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() as RouteBody };
}
async function prepare() {
  const response = await post('/prepare', { keyId: key.id, jwk, host: node.url, permissions });
  expect(response.status).toBe(200);
  return response.body;
}
function approval(prepared: RouteBody) {
  return { keyId: key.id, jwk, host: node.url, permissions, prepared: prepared.prepared,
    protocolVersion: 1, authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys };
}

test('prepare reports every resolved requested space without claiming readiness', async () => {
  const prepared = await prepare();
  expect(prepared.spaceId).toBe(spaces[1]!.spaceId);
  expect(prepared.requestedSpaces).toEqual(spaces.map(space => ({ ...space, spaceReady: null })));
});

test('a fresh managed approval confirms both spaces on the loopback node before reporting ready', async () => {
  const prepared = await prepare();
  const completed = await post('/', approval(prepared));
  expect(completed.status).toBe(200);
  expect(completed.body.requestedSpaces).toEqual(spaces.map(space => ({ ...space, spaceReady: true })));
  expect(completed.body.spaceReady).toBe(true);
  expect(spaces.every(space => node.hosted.has(space.spaceId))).toBe(true);
  expect(new Set(parsePreparedRecap(completed.body.siwe).map(entry => entry.space))).toEqual(new Set(spaces.map(space => space.spaceId)));
});

test('a secondary space still hosting cannot be hidden by a ready primary space', async () => {
  node.hosted.add(spaces[1]!.spaceId);
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  node.beforeHost = async space => { if (space === spaces[0]!.spaceId) await held; };
  try {
    const completed = await post('/', approval(await prepare()));
    expect(completed.status).toBe(200);
    expect(completed.body.spaceReady).toBeNull();
    expect(completed.body.requestedSpaces).toEqual([
      { ...spaces[0]!, spaceReady: null, spacePending: true, spaceError: 'tinycloud_requested_space_timeout' },
      { ...spaces[1]!, spaceReady: true },
    ]);
  } finally { release(); }
});

test('Auto-Sign off leaves an unhosted secondary space not ready even if primary is hosted', async () => {
  autoSignEnabled = false;
  node.hosted.add(spaces[1]!.spaceId);
  const completed = await post('/', approval(await prepare()));
  expect(completed.status).toBe(200);
  expect(completed.body.spaceReady).toBe(false);
  expect(completed.body.requestedSpaces).toEqual([
    { ...spaces[0]!, spaceReady: false }, { ...spaces[1]!, spaceReady: true },
  ]);
});

test('external completion preserves both signed spaces and reports each activation result', async () => {
  for (const space of spaces) node.hosted.add(space.spaceId);
  const prepared = await prepare();
  const completed = await post('/complete', { ...approval(prepared), signature: await account.signMessage({ message: prepared.prepared.siwe }) });
  expect(completed.status).toBe(200);
  expect(completed.body.spaceId).toBe(spaces[1]!.spaceId);
  expect(completed.body.requestedSpaces).toEqual(spaces.map(space => ({ ...space, spaceReady: true })));
  expect(completed.body.spaceReady).toBe(true);
});

test('a changed per-space permission baseline is refused without spending the original context', async () => {
  for (const space of spaces) node.hosted.add(space.spaceId);
  const prepared = await prepare();
  const request = approval(prepared);
  const refused = await post('/', { ...request, permissions: permissions.map(entry => entry.space === 'account' ? { ...entry, space: 'applications' } : entry) });
  expect(refused.status).toBe(400);
  expect((await post('/', request)).status).toBe(200);
});

test('a fully deselected space stays in the requested set and is not hosted or reported ready', async () => {
  const baseline = permissions.filter(entry => entry.service !== 'tinycloud.capabilities');
  node.hosted.add(spaces[0]!.spaceId);
  const initial = await post('/prepare', { keyId: key.id, jwk, host: node.url, permissions: baseline });
  const selection = initial.body.selectedActionKeys.filter(key => key.split('\0')[1] === spaces[0]!.spaceId);
  const narrowed = await post('/prepare', { keyId: key.id, jwk, host: node.url, permissions: baseline, actionKeys: selection });
  expect(narrowed.status).toBe(200);
  expect(narrowed.body.requestedSpaces).toEqual(spaces.map(space => ({ ...space, spaceReady: null })));
  const completed = await post('/', { ...approval(narrowed.body), permissions: baseline });
  expect(completed.status).toBe(200);
  expect(completed.body.requestedSpaces).toEqual([
    { ...spaces[0]!, spaceReady: true }, { ...spaces[1]!, spaceReady: false },
  ]);
  expect(completed.body.spaceReady).toBe(false);
  expect(node.hostPosts.some(post => post.spaceId === spaces[1]!.spaceId)).toBe(false);
});
