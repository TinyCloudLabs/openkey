import { expect, mock, test } from 'bun:test';
import { Hono } from 'hono';

mock.module('@openkey/db', () => ({
  createPrismaClient: () => { throw new Error('database must not be opened by this handler test'); },
  checkRuntimeSchemaContract: async () => ({ ready: true }),
}));
const { readinessHandler } = await import('../readiness');

function healthApp(check: () => Promise<{ ready: boolean }>) {
  const app = new Hono();
  app.get('/health', readinessHandler(check));
  return app;
}

test('readiness HTTP path returns non-2xx when the schema contract fails', async () => {
  const response = await healthApp(async () => ({ ready: false })).request('/health');
  expect(response.status).toBe(503);
  expect(await response.json()).toEqual({ status: 'not_ready' });
});

test('readiness HTTP path returns 200 for a valid schema contract', async () => {
  const response = await healthApp(async () => ({ ready: true })).request('/health');
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ status: 'ok', tee: 'development' });
});
