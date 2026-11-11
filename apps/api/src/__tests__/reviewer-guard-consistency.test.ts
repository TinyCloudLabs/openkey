import { expect, test } from 'bun:test';
import { Hono } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { mockModules } from './mock-module';
import type { ProviderInterceptorDatabase } from '../services/native-delegation/interceptors';

const binding = { userId: 'reviewer', clientId: 'review-client', resource: 'https://mcp.example.test/mcp', installEpoch: 1 };
await mockModules({
  '../services/reviewer-accounts': () => ({
    reviewerForUser: async () => binding,
    reviewerActive: () => true,
    captureReviewer: () => {},
  }),
});
const { createReviewerRouteGuard } = await import('../middleware/reviewer?guard-consistency-test' as string);
const { createProviderInterceptors } = await import('../services/native-delegation/interceptors?guard-consistency-test' as string);

test.each([3599, 3600, 3601])('the Hono guard independently enforces reviewer age at %i seconds', async (age) => {
  const now = Date.now();
  const database = { session: { findUnique: async () => ({
    id: 'session', userId: binding.userId, reviewerEpoch: 1,
    createdAt: new Date(now - age * 1000), expiresAt: new Date(now + 7 * 86400_000),
  }) } } as unknown as PrismaClient;
  const app = new Hono();
  app.use('/api/*', createReviewerRouteGuard(database, async () => ({ userId: binding.userId, sessionId: 'session' })));
  // No delegation resolver or Better Auth hook runs behind this guard.
  app.post('/api/delegate/prepare', (c) => c.json({ reached: true }));
  const response = await app.request('/api/delegate/prepare', { method: 'POST' });
  expect(response.status).toBe(age < 3600 ? 200 : 403);
});

for (const grantType of ['authorization_code', 'refresh_token']) {
  test.each([3599, 3600, 3601])(`${grantType} checks the stored reviewer session age at %i seconds`, async (age) => {
    const now = new Date();
    const session = {
      id: 'session', userId: binding.userId, reviewerEpoch: 1,
      createdAt: new Date(now.getTime() - age * 1000), expiresAt: new Date(now.getTime() + 7 * 86400_000),
      user: { reviewerBinding: binding },
    };
    const token = { userId: binding.userId, clientId: binding.clientId, sessionId: session.id,
      scopes: ['tinycloud:mcp'], createdAt: now, expiresAt: session.expiresAt, revoked: null };
    const database = {
      session: { findUnique: async () => session, findFirst: async () => session },
      oauthClient: { findUnique: async () => ({ disabled: false, public: true }), findMany: async () => [] },
      oauthConsent: { findUnique: async () => ({ scopes: token.scopes, createdAt: new Date(now.getTime() - 1000), reviewerEpoch: 1 }) },
      oauthRefreshToken: { findUnique: async () => token },
      tinyCloudNativeGrant: { findFirst: async () => null },
      $queryRaw: async () => [{ id: session.id }],
    } as unknown as ProviderInterceptorDatabase;
    const app = new Hono();
    app.use('/api/auth/*', createProviderInterceptors({
      database, tokens: {}, getSessionUserId: async () => null,
      authorizationCodes: { find: async () => ({ createdAt: now, value: JSON.stringify({
        type: 'authorization_code', userId: binding.userId, sessionId: session.id, reviewerEpoch: 1,
        authTime: now.getTime(), query: { client_id: binding.clientId, scope: 'tinycloud:mcp' },
      }) }), delete: async () => {} },
      provider: async () => Response.json({ reached: true }),
    }));
    app.post('/api/auth/*', (c) => c.json({ reached: true }));
    const response = await app.request('/api/auth/oauth2/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: grantType, client_id: binding.clientId, resource: binding.resource,
        ...(grantType === 'authorization_code' ? { code: 'test-code' } : { refresh_token: 'test-refresh' }) }),
    });
    expect(response.status, await response.clone().text()).toBe(age < 3600 ? 200 : 400);
    if (age >= 3600) expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
  });
}
