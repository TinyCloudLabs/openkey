import { afterAll, beforeAll, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';

const prisma = {
  $transaction: async (callback: (tx: any) => Promise<unknown>) => callback(prisma),
  $queryRawUnsafe: async () => [],
  user: {
    findUnique: async () => ({
      tinyCloudManageKeyMode: 'APP_MANAGED',
      tinyCloudManageKeyPolicyEpoch: BigInt(0),
    }),
    updateMany: async () => ({ count: 1 }),
  },
  tinyCloudManageKeyAppPreference: {
    updateMany: async () => ({ count: 0 }),
  },
  tinyCloudManageKeyControlEvent: {
    create: async () => ({}),
  },
};

beforeAll(() => {
  mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
  mock.module('../middleware/session', () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', { id: 'user_1' });
      return next();
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

  test('keeps a same-site console control mutation unavailable before cutover', async () => {
    const response = await request('/tinycloud-manage-key', {
      origin: 'https://console.openkey.so',
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      error: 'TinyCloud manage-key controls require the separately authorized schema cutover',
    });
  });
});
