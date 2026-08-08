import { afterAll, beforeAll, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';

const prisma = {};

beforeAll(() => {
  mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
  mock.module('../middleware/session', () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', { id: 'user_1' });
      return next();
    }),
  }));
  mock.module('../services/tinycloud-manage-key-control', () => ({
    controlMutationError: () => null,
    changeTinyCloudManageKeyMode: async () => ({
      kind: 'changed', epoch: 1, mode: 'USER_CONTROLLED_SHARED',
    }),
    changeTinyCloudManageKeyGrant: async () => ({
      kind: 'changed', epoch: 1, grant: { enabled: true, status: 'ENABLED' },
    }),
  }));
  process.env.CORS_ORIGIN = 'https://openkey.test';
  process.env.TEE_MODE = 'production';
});

afterAll(() => {
  mock.restore();
  delete process.env.CORS_ORIGIN;
  delete process.env.TEE_MODE;
});

async function request(path: string, headers: Record<string, string>) {
  const { accountRouter } = await import('../routes/account?tinycloud-control-auth-test' as string);
  return accountRouter.request(path, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({
      mode: 'USER_CONTROLLED_SHARED',
      enabled: true,
      expectedEpoch: 0,
      confirmation: 'TAKE CONTROL',
    }),
  });
}

describe('TinyCloud signing control authentication boundary', () => {
  test.each(['/tinycloud-manage-key', '/tinycloud-apps/confidential-client'])(
    'rejects an OAuth bearer token on %s before any control mutation',
    async (path) => {
      const response = await request(path, {
        origin: 'https://openkey.test', authorization: 'Bearer oauth-access-token',
      });
      expect(response.status).toBe(403);
      expect(await response.json()).toEqual({ error: 'Bearer tokens cannot change TinyCloud signing controls' });
    },
  );

  test('rejects a cookie-session control mutation without a same-site origin', async () => {
    const response = await request('/tinycloud-manage-key', {});
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: 'A same-site browser Origin is required' });
  });

  test('allows a console control mutation in the sealed production origin shape', async () => {
    const response = await request('/tinycloud-manage-key', {
      origin: 'https://console.openkey.so',
    });
    expect(response.status).toBe(200);
  });
});
