// TC-688 follow-up: every session-authenticated router outside keys/account
// also refuses a bearer session token unless it comes from an OpenKey web
// origin. /api/delegate/sign keeps its OAuth-only signer auth, and the
// unauthenticated device-authorization endpoints the CLI calls are unchanged.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import { mockModules, replaceModules } from './mock-module';

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

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      sessionResolutions += 1;
      c.set('user', { id: 'user_1', email: 'user@example.com' });
      c.set('session', { id: 'session_1', userId: 'user_1', expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: async () => new Uint8Array(32), getQuote: async () => 'quote', isInTee: () => false }),
  }),
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrapForApprovedSign: async () => ({ status: 'complete' }),
  }),
});

const savedEnv = {
  CORS_ORIGIN: process.env.CORS_ORIGIN,
  WEBAUTHN_ORIGIN: process.env.WEBAUTHN_ORIGIN,
  TEE_MODE: process.env.TEE_MODE,
  CONSOLE_ORIGIN: process.env.CONSOLE_ORIGIN,
};

beforeAll(async () => {
  process.env.CORS_ORIGIN = `${OPENKEY_ORIGIN},https://console.openkey.so`;
  process.env.WEBAUTHN_ORIGIN = OPENKEY_ORIGIN;
  process.env.CONSOLE_ORIGIN = 'https://console.openkey.so';
  const delegate = await import('../routes/delegate?bearer-origin-routes' as string);
  const { accountRouter } = await import('../routes/account?bearer-origin-routes' as string);
  const { keysRouter } = await import('../routes/keys?bearer-origin-routes' as string);
  const { approvalRequestRouter } = await import('../routes/approval-requests?bearer-origin-routes' as string);
  const { nostrKeysRouter } = await import('../routes/nostr-keys?bearer-origin-routes' as string);
  const { preparedHandoffRouter } = await import('../routes/prepared-handoffs?bearer-origin-routes' as string);
  const { createOwnerRevocationRouter } = await import('../routes/owner-revocation?bearer-origin-routes' as string);
  const { PreparedHandoffService } = await import('../services/prepared-handoff');
  const { secretsRouter } = await import('../routes/secrets?bearer-origin-routes' as string);
  const { variablesRouter } = await import('../routes/variables?bearer-origin-routes' as string);
  const { organizationsRouter } = await import('../routes/organizations?bearer-origin-routes' as string);
  const { tenantConsoleRouter } = await import('../routes/tenant-console?bearer-origin-routes' as string);
  const { deviceAuthorizationRouter } = await import('../routes/device-authorization?bearer-origin-routes' as string);
  delegate.setDelegateSignerAuthMiddlewareForTests(createMiddleware(async (c) => {
    signerAuthCalls += 1;
    return c.json({ signerAuth: true }, 401);
  }) as any);

  const ownerRevocationRouter = createOwnerRevocationRouter(
    new PreparedHandoffService(new Proxy({}, { get: () => async () => null }) as never),
    { findKey: async () => null, signManaged: async () => '' },
    createMiddleware(async (c, next) => {
      sessionResolutions += 1;
      c.set('user', { id: 'user_1', email: 'user@example.com' });
      c.set('session', { id: 'session_1', userId: 'user_1', expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }) as never,
  );
  // Mounted as apps/api/src/index.ts mounts them.
  app = new Hono();
  app.route('/api/account', accountRouter);
  app.route('/api/keys', keysRouter);
  app.route('/api/keys/nostr', nostrKeysRouter);
  app.route('/api', approvalRequestRouter);
  app.route('/api/delegate/handoffs', preparedHandoffRouter);
  app.route('/api/delegate/owner-revocation', ownerRevocationRouter);
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
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
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
  ['GET', '/api/account'],
  ['GET', '/api/keys'],
  ['POST', '/api/approval-requests/appr_1/deny'],
  ['POST', '/api/device-authorizations/tx_1/approve'],
  ['POST', '/api/device-authorizations/tx_1/deny'],
  ['POST', '/api/delegate/prepare'],
  ['POST', '/api/delegate/owner-revocation/prepare'],
  ['GET', '/api/delegate/handoffs/available'],
  ['POST', '/api/delegate/handoffs/claim'],
  ['GET', '/api/secrets'],
  ['GET', '/api/variables'],
  ['GET', '/api/keys/nostr'],
  ['POST', '/api/keys/nostr'],
  ['DELETE', '/api/keys/nostr/grants/grant_1'],
  ['GET', '/api/organizations'],
  ['GET', '/api/console/organizations/org_1/overview'],
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
    expect(sessionResolutions).toBeGreaterThan(0);
  });

  test.each(sessionRoutes)('%s %s still resolves a cookie session', async (method, path) => {
    await call(method, path, { origin: OPENKEY_ORIGIN });
    expect(sessionResolutions).toBeGreaterThan(0);
  });
  test('console-origin bearers are refused on every sensitive route group', async () => {
    const sensitive = sessionRoutes.filter(([, path]) =>
      !path.startsWith('/api/organizations') && !path.startsWith('/api/console/organizations'),
    );
    for (const [method, path] of sensitive) {
      const response = await call(method, path, {
        authorization: 'Bearer leaked-session-token',
        origin: 'https://console.openkey.so',
      });
      expect(response.status, `${method} ${path}`).toBe(403);
      expect(sessionResolutions, `${method} ${path} session`).toBe(0);
    }
  });

  test.each(['Bearer widget-session-token', undefined])(
    'console-origin organization routes accept %s',
    async (authorization) => {
      for (const path of ['/api/organizations', '/api/console/organizations/org_1/overview']) {
        sessionResolutions = 0;
        const response = await call('GET', path, {
          origin: 'https://console.openkey.so',
          ...(authorization ? { authorization } : {}),
        });
        expect(response.status, path).not.toBe(403);
        expect(sessionResolutions, path).toBe(1);
      }
    },
  );
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
