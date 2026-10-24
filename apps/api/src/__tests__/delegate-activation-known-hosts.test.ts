// TC-1949: the approval routes (`POST /api/delegate` versioned and legacy, `POST
// /api/delegate/complete`) only activate the signed session on known TinyCloud
// hosts: the allowlisted nodes, and loopback outside production. Any other host
// gets `hostActivated: false` and no request to it; the web page activates on
// its own.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { SpaceHostResult } from '@tinycloud/sdk-core';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { mockModules, replaceModules } from './mock-module';

// Never touch a real home: HOME and every tool home point at a private temp dir.
const tempHome = mkdtempSync('/var/tmp/tc1949.');
const savedEnv: Record<string, string | undefined> = {};
for (const name of ['HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'NODE_ENV', 'TEE_MODE', 'TINYCLOUD_BOOTSTRAP_HOST', 'TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS']) {
  savedEnv[name] = process.env[name];
}
afterAll(() => {
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(tempHome, { recursive: true, force: true });
});
process.env.HOME = tempHome;
process.env.BUN_INSTALL_CACHE_DIR = `${tempHome}/bun-cache`;
process.env.XDG_CONFIG_HOME = `${tempHome}/config`;
process.env.XDG_CACHE_HOME = `${tempHome}/cache`;
process.env.XDG_DATA_HOME = `${tempHome}/data`;
if (!process.env.HOME?.startsWith('/var/tmp/tc1949.')) throw new Error('test HOME is not the private temp dir');

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const keyRecord: {
  id: string; userId: string; address: string; keyType: 'MANAGED' | 'EXTERNAL';
  archivedAt: null; sealedBlob: string | null; sealingContext: null;
} = {
  id: 'key_1',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};

const activateSessionWithHost = mock(async (_host: string, _header: { Authorization: string }): Promise<SpaceHostResult> => ({
  success: true,
  status: 200,
}));
const ensureTinyCloudBootstrap = mock(async () => ({ status: 'complete' as const }));

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({
      deriveKey: mock(async () => new Uint8Array(32)),
      getQuote: mock(async () => 'quote'),
      isInTee: () => false,
    }),
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
  '../services/tinycloud-bootstrap': (actual) => ({
    ensureTinyCloudBootstrap,
    isTinyCloudBootstrapComplete: mock(async () => false),
    trustedTinyCloudBootstrapHost: actual.trustedTinyCloudBootstrapHost,
  }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?activation-known-hosts-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?activation-known-hosts-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

beforeEach(() => {
  process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = 'off';
  delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  resetContexts?.();
  keyRecord.keyType = 'MANAGED';
  keyRecord.sealedBlob = 'sealed-blob';
  activateSessionWithHost.mockClear();
  activateSessionWithHost.mockImplementation(async () => ({ success: true, status: 200 }));
  ensureTinyCloudBootstrap.mockClear();
});

afterEach(() => {
  for (const name of ['NODE_ENV', 'TEE_MODE']) {
    const value = savedEnv[name];
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

function setProduction() {
  process.env.NODE_ENV = 'production';
  process.env.TEE_MODE = 'production';
}

function setDevelopment() {
  process.env.NODE_ENV = 'development';
  delete process.env.TEE_MODE;
}

type PostResult = { status: number; body: Record<string, any> };

async function post(path: string, body: Record<string, unknown>): Promise<PostResult> {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function prepare(host: string) {
  const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host });
  expect(prepared.status).toBe(200);
  return prepared.body;
}

/** The managed key's versioned approval: POST / with the /prepare context. */
async function managedVersioned(host: string) {
  const prepared = await prepare(host);
  return post('/', {
    keyId: keyRecord.id,
    jwk,
    host,
    prepared: prepared.prepared,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
    protocolVersion: 1,
  });
}

/** The managed key's token-less approval: POST / with no /prepare context. */
async function managedLegacy(host: string) {
  return post('/', { keyId: keyRecord.id, jwk, host });
}

/** The external key's completion: POST /complete with the wallet signature. */
async function externalComplete(host: string) {
  keyRecord.keyType = 'EXTERNAL';
  keyRecord.sealedBlob = null;
  const prepared = await prepare(host);
  return post('/complete', {
    prepared: prepared.prepared,
    signature: await account.signMessage({ message: prepared.prepared.siwe }),
    host,
    jwk,
    edited: false,
    protocolVersion: 1,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
  });
}

const routes = {
  'managed key, versioned POST /': managedVersioned,
  'managed key, legacy POST /': managedLegacy,
  'external key, POST /complete': externalComplete,
};

const trustedHosts = ['https://node.tinycloud.xyz', 'https://tee.node.tinycloud.xyz'];
const untrustedHosts = [
  'https://untrusted.example',
  'https://node.tinycloud.xyz.untrusted.example',
  'http://node.tinycloud.xyz',
  'https://node.tinycloud.xyz:8443',
  'http://10.0.0.5:8080',
  'http://192.168.1.10:8080',
];
const loopbackHosts = ['http://127.0.0.1:8000', 'http://localhost:8000', 'http://[::1]:8000'];

function expectNotActivated(result: PostResult) {
  expect(result.status).toBe(200);
  expect(result.body.hostActivated).toBe(false);
  expect(typeof result.body.delegationHeader?.Authorization).toBe('string');
  expect(activateSessionWithHost).not.toHaveBeenCalled();
  expect(ensureTinyCloudBootstrap).not.toHaveBeenCalled();
}

for (const [label, run] of Object.entries(routes)) {
  describe(`session activation host: ${label}`, () => {
    test('test HOME is the private temp dir', () => {
      expect(process.env.HOME).toBe(tempHome);
    });

    for (const host of trustedHosts) {
      test(`production: ${host} is activated`, async () => {
        setProduction();
        const result = await run(host);
        expect(result.status).toBe(200);
        expect(result.body.hostActivated).toBe(true);
        expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
        expect(activateSessionWithHost.mock.calls[0]![0]).toBe(host);
      });
    }

    for (const host of untrustedHosts) {
      test(`production: ${host} is not contacted`, async () => {
        setProduction();
        expectNotActivated(await run(host));
      });

      test(`development: ${host} is not contacted`, async () => {
        setDevelopment();
        expectNotActivated(await run(host));
      });
    }

    for (const host of loopbackHosts) {
      test(`production: ${host} is not contacted`, async () => {
        setProduction();
        expectNotActivated(await run(host));
      });

      test(`development: ${host} is activated`, async () => {
        setDevelopment();
        const result = await run(host);
        expect(result.status).toBe(200);
        expect(result.body.hostActivated).toBe(true);
        expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
        expect(activateSessionWithHost.mock.calls[0]![0]).toBe(host);
      });
    }

    test('production: a configured loopback bootstrap host does not make loopback requests contactable', async () => {
      setProduction();
      process.env.TINYCLOUD_BOOTSTRAP_HOST = 'http://127.0.0.1:8000';
      expectNotActivated(await run('http://127.0.0.1:8000'));
    });
  });
}
