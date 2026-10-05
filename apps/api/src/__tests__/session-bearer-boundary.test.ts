// TC-688 / TC-689: a Better Auth session token presented as a bearer from
// outside OpenKey cannot reach key signing, key management or account routes,
// and account deletion requires a fresh passkey on a cookie session.
//
// Run this file on its own: bun's module mocks leak across test files.
import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';

const OPENKEY_ORIGIN = 'https://openkey.test';
const SESSION_TOKEN = 'leaked-session-token';
const now = Date.now();

let sessionResolutions = 0;
let signCalls = 0;
let deletedUsers: string[] = [];
let lastPasskeyAt: Date | null = null;
let sessionLookups: unknown[] = [];

const tx = {
  ethereumKey: { deleteMany: async () => ({ count: 1 }) },
  passkey: { deleteMany: async () => ({ count: 1 }) },
  session: { deleteMany: async () => ({ count: 1 }) },
  account: { deleteMany: async () => ({ count: 1 }) },
  verification: { deleteMany: async () => ({ count: 0 }) },
  user: { delete: async ({ where }: { where: { id: string } }) => { deletedUsers.push(where.id); return {}; } },
};

const prisma = {
  $transaction: async (callback: (client: typeof tx) => Promise<unknown>) => callback(tx),
  ethereumKey: {
    findMany: async () => [],
    findFirst: async () => ({
      id: 'key_1', userId: 'user_1', address: '0x0000000000000000000000000000000000000001',
      keyType: 'MANAGED', sealedBlob: 'sealed', archivedAt: null,
    }),
    updateMany: async () => ({ count: 1 }),
    count: async () => 1,
  },
  nostrKey: { findFirst: async () => null, findMany: async () => [] },
  session: {
    findFirst: async (args: unknown) => {
      sessionLookups.push(args);
      return { lastPasskeyAt };
    },
  },
  user: {
    findUnique: async () => ({ autoSignEnabled: true }),
    update: async ({ data }: { data: { autoSignEnabled: boolean } }) => ({ autoSignEnabled: data.autoSignEnabled }),
  },
};

beforeAll(async () => {
  const realTee = await import('@openkey/tee');
  process.env.CORS_ORIGIN = OPENKEY_ORIGIN;
  process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS = '10';
  mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
  mock.module('@openkey/tee', () => ({
    ...realTee,
    createTeeClient: () => ({ deriveKey: async () => new Uint8Array(32), getQuote: async () => 'quote', isInTee: () => false }),
    seal: async () => 'sealed',
    unseal: async () => `0x${'11'.repeat(32)}`,
    generatePrivateKey: () => `0x${'11'.repeat(32)}`,
    getAddressFromPrivateKey: () => '0x0000000000000000000000000000000000000001',
    createWalletFromPrivateKey: () => ({
      signMessage: async () => { signCalls += 1; return '0xsig'; },
      signTypedData: async () => { signCalls += 1; return '0xsig'; },
    }),
  }));
  mock.module('../services/tinycloud-bootstrap', () => ({
    ensureTinyCloudBootstrapForApprovedSign: async () => ({ status: 'complete' }),
  }));
  // Stands in for Better Auth: every request resolves to user_1's session.
  // The boundary must reject untrusted bearers before this runs.
  mock.module('../middleware/session', () => ({
    requireSession: createMiddleware(async (c, next) => {
      sessionResolutions += 1;
      c.set('user', { id: 'user_1', email: 'user@example.com' });
      c.set('session', { id: 'session_1', userId: 'user_1', expiresAt: new Date(now + 60_000) });
      await next();
    }),
  }));
});

afterAll(() => {
  mock.restore();
  delete process.env.CORS_ORIGIN;
  delete process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
});

beforeEach(() => {
  sessionResolutions = 0;
  signCalls = 0;
  deletedUsers = [];
  lastPasskeyAt = null;
  sessionLookups = [];
});

// Mounted exactly as apps/api/src/index.ts mounts them.
async function api() {
  const { keysRouter } = await import('../routes/keys');
  const { nostrKeysRouter } = await import('../routes/nostr-keys');
  const { accountRouter } = await import('../routes/account');
  const app = new Hono();
  app.route('/api/keys', keysRouter);
  app.route('/api/keys/nostr', nostrKeysRouter);
  app.route('/api/account', accountRouter);
  return app;
}

async function call(
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: unknown,
) {
  const app = await api();
  return app.request(path, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const custodyRoutes: Array<[string, string, unknown?]> = [
  ['POST', '/api/keys/key_1/sign', { message: 'hello' }],
  ['POST', '/api/keys/key_1/sign-typed-data', { domain: {}, types: {}, primaryType: 'Mail', message: {} }],
  ['POST', '/api/keys/key_1/archive'],
  ['POST', '/api/keys/generate', {}],
  ['GET', '/api/keys'],
  ['POST', '/api/keys/nostr', {}],
  ['GET', '/api/account'],
  ['PATCH', '/api/account/auto-sign', { autoSignEnabled: false }],
  ['POST', '/api/account/delete', { confirmation: 'DELETE MY ACCOUNT' }],
];

describe('bearer session tokens from outside OpenKey (TC-688)', () => {
  test.each(custodyRoutes)('%s %s refuses a bearer sent by a server', async (method, path, body) => {
    const response = await call(method, path, { authorization: `Bearer ${SESSION_TOKEN}` }, body);
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: 'Bearer session tokens are accepted only from OpenKey' });
    expect(sessionResolutions).toBe(0);
    expect(signCalls).toBe(0);
    expect(deletedUsers).toEqual([]);
  });

  test.each(custodyRoutes)('%s %s refuses a bearer sent from an embedding site', async (method, path, body) => {
    const response = await call(method, path, {
      authorization: `Bearer ${SESSION_TOKEN}`, origin: 'https://embedder.example',
    }, body);
    expect(response.status).toBe(403);
    expect(sessionResolutions).toBe(0);
    expect(signCalls).toBe(0);
  });

  test('the OpenKey embedded widget can still sign with its bearer', async () => {
    const response = await call('POST', '/api/keys/key_1/sign-typed-data', {
      authorization: `Bearer ${SESSION_TOKEN}`, origin: OPENKEY_ORIGIN,
    }, { domain: {}, types: {}, primaryType: 'Mail', message: {} });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ signature: '0xsig', address: '0x0000000000000000000000000000000000000001' });
    expect(signCalls).toBe(1);
  });

  test('the OpenKey embedded widget can still list keys with its bearer', async () => {
    const response = await call('GET', '/api/keys', { authorization: `Bearer ${SESSION_TOKEN}`, origin: OPENKEY_ORIGIN });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ keys: [] });
  });

  test('cookie sessions without an Authorization header are unchanged', async () => {
    const response = await call('GET', '/api/keys');
    expect(response.status).toBe(200);
    expect(sessionResolutions).toBe(1);
  });
});

describe('account controls (TC-689)', () => {
  test('auto-sign refuses a bearer even from OpenKey', async () => {
    const response = await call('PATCH', '/api/account/auto-sign', {
      authorization: `Bearer ${SESSION_TOKEN}`, origin: OPENKEY_ORIGIN,
    }, { autoSignEnabled: false });
    expect(response.status).toBe(403);
  });

  test('auto-sign refuses a cookie request without an OpenKey origin', async () => {
    const response = await call('PATCH', '/api/account/auto-sign', {}, { autoSignEnabled: false });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: 'A same-site browser Origin is required' });
  });

  test('the dashboard can still change auto-sign', async () => {
    const response = await call('PATCH', '/api/account/auto-sign', { origin: OPENKEY_ORIGIN }, { autoSignEnabled: false });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ autoSignEnabled: false });
  });

  test('delete refuses a bearer even from OpenKey', async () => {
    lastPasskeyAt = new Date();
    const response = await call('POST', '/api/account/delete', {
      authorization: `Bearer ${SESSION_TOKEN}`, origin: OPENKEY_ORIGIN,
    }, { confirmation: 'DELETE MY ACCOUNT' });
    expect(response.status).toBe(403);
    expect(deletedUsers).toEqual([]);
  });

  test('delete requires a passkey verification on this session', async () => {
    const response = await call('POST', '/api/account/delete', { origin: OPENKEY_ORIGIN }, { confirmation: 'DELETE MY ACCOUNT' });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: 'Verify with your passkey again to continue',
      code: 'passkey_step_up_required',
    });
    expect(deletedUsers).toEqual([]);
    expect(sessionLookups).toHaveLength(1);
    expect(sessionLookups[0]).toMatchObject({ where: { id: 'session_1', userId: 'user_1' } });
  });

  test('delete refuses a passkey verification older than five minutes', async () => {
    lastPasskeyAt = new Date(Date.now() - 5 * 60 * 1000 - 1_000);
    const response = await call('POST', '/api/account/delete', { origin: OPENKEY_ORIGIN }, { confirmation: 'DELETE MY ACCOUNT' });
    expect(response.status).toBe(403);
    expect(deletedUsers).toEqual([]);
  });

  test('delete refuses a passkey timestamp in the future', async () => {
    lastPasskeyAt = new Date(Date.now() + 60_000);
    const response = await call('POST', '/api/account/delete', { origin: OPENKEY_ORIGIN }, { confirmation: 'DELETE MY ACCOUNT' });
    expect(response.status).toBe(403);
    expect(deletedUsers).toEqual([]);
  });

  test('delete proceeds after a fresh passkey verification and typed confirmation', async () => {
    lastPasskeyAt = new Date(Date.now() - 60_000);
    const response = await call('POST', '/api/account/delete', { origin: OPENKEY_ORIGIN }, { confirmation: 'DELETE MY ACCOUNT' });
    expect(response.status).toBe(200);
    expect(deletedUsers).toEqual(['user_1']);
  });

  test('delete still requires the typed confirmation', async () => {
    lastPasskeyAt = new Date();
    const response = await call('POST', '/api/account/delete', { origin: OPENKEY_ORIGIN }, { confirmation: 'yes' });
    expect(response.status).toBe(400);
    expect(deletedUsers).toEqual([]);
  });

  test('the unimplemented email deletion request says so', async () => {
    const response = await call('POST', '/api/account/delete/request', { origin: OPENKEY_ORIGIN });
    expect(response.status).toBe(501);
  });
});
