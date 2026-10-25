// Unauthenticated requests to the delegate routes are refused with a JSON 401.
// The router has its own onError, so a refusal that is dropped instead of
// returned becomes an empty 200 (Content-Length 0, no Content-Type).

import './tc1777-test-env';
import { beforeAll, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const ORIGIN = 'https://listen.tinycloud.xyz';
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;

let signed: string[] = [];
let manifestBindResult: { ok: boolean; manifest?: Record<string, unknown>; fetchedDigest?: string; reason?: string } = {
  ok: true,
  fetchedDigest: 'a'.repeat(64),
  manifest: { name: 'Listen', appId: 'xyz.tinycloud.listen', prefix: 'xyz.tinycloud.listen' },
};
const fetchAndBindWellKnownManifest = mock(async () => manifestBindResult);

const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== user.id) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};

// The session middleware as session.ts has it (`requireSession`), over a session
// lookup that answers only for requests that carry `x-test-session: valid`.
const requireSession = createMiddleware(async (c, next) => {
  const session = c.req.header('x-test-session') === 'valid'
    ? { user, session: { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) } }
    : null;
  if (!session) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  c.set('user', session.user);
  c.set('session', session.session);
  await next();
});

replaceModules({
  '../middleware/session': () => ({ requireSession }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return {
        ...wallet,
        signMessage: async (args: { message: string }) => {
          signed.push(args.message);
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }),
  '../services/manifest-origin-fetch': () => ({ fetchAndBindWellKnownManifest }),
});


let router: typeof import('../routes/delegate')['delegateRouter'];
beforeAll(async () => {
  ({ delegateRouter: router } = await import('../routes/delegate?unauthenticated' as string));
});

function call(path: string, headers: Record<string, string> = {}) {
  return router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://openkey.so', ...headers },
    body: '{}',
  });
}

const ROUTES = ['/authorize-sign-prepare', '/authorize-sign-preview', '/authorize-sign', '/prepare', '/complete', '/'];

describe('delegate routes without a session', () => {
  test.each(ROUTES)('POST %s answers a JSON 401, not an empty 200', async (path) => {
    const res = await call(path);
    expect(res.status).toBe(401);
    expect(res.headers.get('content-type')).toContain('application/json');
    await expect(res.json()).resolves.toEqual({ error: 'Unauthorized' });
    expect(signed).toEqual([]);
  });

  test.each(ROUTES)('POST %s with a cookie that holds no session answers the same', async (path) => {
    const res = await call(path, { cookie: 'tc2022=1' });
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({ error: 'Unauthorized' });
  });

  test('a bearer token that holds no session answers 401', async () => {
    const res = await call('/authorize-sign-prepare', { authorization: 'Bearer none', origin: 'http://localhost:5173' });
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({ error: 'Unauthorized' });
  });

  test('a bearer token from a site that is not an OpenKey web origin answers 403', async () => {
    const res = await call('/authorize-sign-prepare', { authorization: 'Bearer any', origin: 'https://app.example' });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual({ error: 'Bearer session tokens are accepted only from OpenKey' });
  });
});

describe('delegate routes with a session', () => {
  test.each(ROUTES)('POST %s reaches the route', async (path) => {
    const res = await call(path, { 'x-test-session': 'valid' });
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
    expect(res.headers.get('content-type')).toContain('application/json');
  });
});
