import { expect, test } from 'bun:test';
import { Hono } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { mockModules } from './mock-module';

// TC-3232 + TC-2775: once a Terms release is configured, a review account can only get past the gate by
// reading and accepting the Terms, so the reviewer guard must let exactly those two calls through.
let binding = { store: 'openai', userId: 'reviewer', clientId: 'review-client', installEpoch: 1 };
await mockModules({
  '../services/reviewer-accounts': () => ({
    reviewerForUser: async () => binding,
    reviewerActive: () => true,
    captureReviewer: () => {},
  }),
});
// Imported after the mock, under a file-specific query (TC-928), so it binds the mocked reviewer module.
const { createReviewerRouteGuard } = await import('../middleware/reviewer?reviewer-terms-allowlist-test' as string);

const now = Date.now();
const database = { session: { findUnique: async () => ({
  id: 'session', userId: 'reviewer', reviewerEpoch: 1,
  createdAt: new Date(now - 60_000), expiresAt: new Date(now + 3_000_000),
}) } } as unknown as PrismaClient;

for (const store of ['openai', 'apple']) {
  test.each([
    ['GET', '/api/account/terms', 200],
    ['POST', '/api/account/terms/accept', 200],
    ['POST', '/api/account/terms/withdraw', 403],
    ['GET', '/api/account/keys', 403],
  ] as const)(`${store} reviewer: %s %s answers %i`, async (method, path, status) => {
    binding = { ...binding, store };
    const app = new Hono();
    app.use('/api/*', createReviewerRouteGuard(database, async () => [{ userId: 'reviewer', sessionId: 'session' }]));
    app.all('/api/*', (c) => c.json({ reached: true }));
    expect((await app.request(path, { method })).status).toBe(status);
  });
}
