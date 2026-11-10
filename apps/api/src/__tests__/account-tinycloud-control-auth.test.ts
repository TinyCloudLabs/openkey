import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { mockModules, replaceModules } from './mock-module';

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

// Restored afterwards: other files in the same `bun test` run read these.
const savedEnv = { CORS_ORIGIN: process.env.CORS_ORIGIN, WEBAUTHN_ORIGIN: process.env.WEBAUTHN_ORIGIN, TEE_MODE: process.env.TEE_MODE };

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', { id: 'user_1' });
      return next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
});

beforeAll(() => {
  process.env.WEBAUTHN_ORIGIN = 'https://openkey.test';
  process.env.TEE_MODE = 'production';
});

afterAll(() => {
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
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

  test('refuses a console cookie control mutation but allows the account origin', async () => {
    const consoleResponse = await request('/tinycloud-manage-key', {
      origin: 'https://console.openkey.so',
    });
    expect(consoleResponse.status).toBe(403);

    const accountResponse = await request('/tinycloud-manage-key', {
      origin: 'https://openkey.test',
    });
    expect(accountResponse.status).toBe(200);
  });
});
