// TC-688 follow-up: every session-authenticated router outside keys/account
// also refuses a bearer session token unless it comes from an OpenKey web
// origin. /api/delegate/sign keeps its OAuth-only signer auth, and the
// unauthenticated device-authorization endpoints the CLI calls are unchanged.
//
// Run this file on its own: bun's module mocks leak across test files.
import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';

const OPENKEY_ORIGIN = 'https://openkey.test';
const GUARD_ERROR = { error: 'Bearer session tokens are accepted only from OpenKey' };

let sessionResolutions = 0;
let signerAuthCalls = 0;

// Every Prisma model method resolves to null; routes past the guard may then
// fail, which these tests do not inspect.
const model: any = new Proxy({}, { get: () => async () => null });
const prisma: any = new Proxy({}, {
  get: (_target, key) => (key === '$transaction' ? async (fn: any) => fn(prisma) : model),
});

let app: Hono;

beforeAll(async () => {
  const realTee = await import('@openkey/tee');
  process.env.CORS_ORIGIN = OPENKEY_ORIGIN;
  mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
  mock.module('@openkey/tee', () => ({
    ...realTee,
    createTeeClient: () => ({ deriveKey: async () => new Uint8Array(32), getQuote: async () => 'quote', isInTee: () => false }),
  }));
  mock.module('../services/tinycloud-bootstrap', () => ({
    ensureTinyCloudBootstrapForApprovedSign: async () => ({ status: 'complete' }),
  }));
  mock.module('../middleware/session', () => ({
    requireSession: createMiddleware(async (c, next) => {
      sessionResolutions += 1;
      c.set('user', { id: 'user_1', email: 'user@example.com' });
      c.set('session', { id: 'session_1', userId: 'user_1', expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }));

  const delegate = await import('../routes/delegate');
  const { secretsRouter } = await import('../routes/secrets');
  const { variablesRouter } = await import('../routes/variables');
  const { organizationsRouter } = await import('../routes/organizations');
  const { tenantConsoleRouter } = await import('../routes/tenant-console');
  const { deviceAuthorizationRouter } = await import('../routes/device-authorization');
  delegate.setDelegateSignerAuthMiddlewareForTests(createMiddleware(async (c) => {
    signerAuthCalls += 1;
    return c.json({ signerAuth: true }, 401);
  }) as any);

  // Mounted as apps/api/src/index.ts mounts them.
  app = new Hono();
  app.route('/api/secrets', secretsRouter);
  app.route('/api/variables', variablesRouter);
  app.route('/api/delegate', delegate.delegateRouter);
  app.route('/api/device-authorizations', deviceAuthorizationRouter);
  app.route('/api/organizations', organizationsRouter);
  app.route('/api/console/organizations', tenantConsoleRouter);
  // Handlers past the boundary fail against the null Prisma stub; that is
  // outside what these tests check.
  app.onError((_error, c) => c.json({ error: 'handler failed after authentication' }, 500));
});

afterAll(() => {
  mock.restore();
  delete process.env.CORS_ORIGIN;
});

beforeEach(() => {
  sessionResolutions = 0;
  signerAuthCalls = 0;
});

function call(method: string, path: string, headers: Record<string, string>) {
  return app.request(path, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: method === 'GET' ? undefined : '{}',
  });
}

const sessionRoutes: Array<[string, string]> = [
  ['POST', '/api/delegate'],
  ['POST', '/api/delegate/prepare'],
  ['POST', '/api/delegate/complete'],
  ['POST', '/api/delegate/authorize-sign-prepare'],
  ['POST', '/api/delegate/authorize-sign-preview'],
  ['POST', '/api/delegate/authorize-sign'],
  ['GET', '/api/secrets'],
  ['GET', '/api/variables'],
  ['GET', '/api/organizations'],
  ['GET', '/api/console/organizations/org_1/overview'],
  ['POST', '/api/device-authorizations/tx_1/approve'],
];

describe('session routes refuse a bearer from outside OpenKey', () => {
  test.each(sessionRoutes)('%s %s refuses a bearer sent by a server', async (method, path) => {
    const response = await call(method, path, { authorization: 'Bearer leaked-session-token' });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual(GUARD_ERROR);
    expect(sessionResolutions).toBe(0);
  });

  test.each(sessionRoutes)('%s %s refuses a bearer sent from an embedding site', async (method, path) => {
    const response = await call(method, path, {
      authorization: 'Bearer leaked-session-token', origin: 'https://embedder.example',
    });
    expect(response.status).toBe(403);
    expect(sessionResolutions).toBe(0);
  });

  test.each(sessionRoutes)('%s %s still resolves an OpenKey widget bearer', async (method, path) => {
    await call(method, path, { authorization: 'Bearer widget-session-token', origin: OPENKEY_ORIGIN });
    expect(sessionResolutions).toBe(1);
  });

  test.each(sessionRoutes)('%s %s still resolves a cookie session', async (method, path) => {
    await call(method, path, { origin: OPENKEY_ORIGIN });
    expect(sessionResolutions).toBe(1);
  });
});

describe('routes outside the session boundary are unchanged', () => {
  test('/api/delegate/sign keeps OAuth signer auth for a server-side bearer', async () => {
    const response = await call('POST', '/api/delegate/sign', { authorization: 'Bearer oauth-access-token' });
    expect(await response.json()).toEqual({ signerAuth: true });
    expect(signerAuthCalls).toBe(1);
    expect(sessionResolutions).toBe(0);
  });

  test.each([
    ['POST', '/api/device-authorizations'],
    ['POST', '/api/device-authorizations/token'],
    ['GET', '/api/device-authorizations/lookup?user_code=ABCD-EFGH'],
  ])('%s %s (CLI device flow) is not origin-gated', async (method, path) => {
    const response = await call(method, path, { authorization: 'Bearer anything' });
    expect(response.status).not.toBe(403);
    expect(await response.text()).not.toContain(GUARD_ERROR.error);
  });
});
