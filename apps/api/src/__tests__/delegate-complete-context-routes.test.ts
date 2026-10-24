// TC-587: `/api/delegate/complete` (and the managed approval) check every
// binding before consuming the single-use authorization context. A refused
// request leaves the pending approval usable; a successful completion
// consumes it exactly once, also under concurrent completions.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, setSystemTime, spyOn, test } from 'bun:test';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { Hono } from 'hono';
import { requestLogger, apiErrorHandler } from '../log';
import type { ApiEnv } from '../log';
import { privateKeyToAccount } from 'viem/accounts';
import type { SpaceHostResult, activateSessionWithHost as ActivateSessionWithHost } from '@tinycloud/sdk-core';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const other = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const user = { id: 'user_1', email: 'alice@example.test' };
const otherUser = { id: 'user_2', email: 'mallory@example.test' };
let currentUser = user;
let autoSignEnabled = true;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
let bootstrapComplete = false;
const otherJwk = { kty: 'OKP', crv: 'Ed25519', x: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' };
const host = 'https://node.tinycloud.xyz';
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
  user: { findUnique: mock(async () => ({ autoSignEnabled })) },
  tinyCloudBootstrapState: {},
};

const activateSessionWithHost = mock(async (_host: string, _header: { Authorization: string }): Promise<SpaceHostResult> => ({
  success: true,
  status: 200,
}));
let realActivateSessionWithHost: typeof ActivateSessionWithHost;
const ensureTinyCloudBootstrap = mock(async () => ({ status: 'complete' as const }));
const isTinyCloudBootstrapComplete = mock(async () => bootstrapComplete);
const deviceService = new DeviceAuthorizationService(new MemoryDeviceAuthorizationStore(), {
  verificationOrigin: 'https://openkey.so',
  encryptionSecret: 'test-device-authorization-secret-is-long-enough',
});

const unseal = mock(async () => privateKey);

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', currentUser);
      c.set('session', { id: 'session_1', userId: currentUser.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
  '../routes/device-authorization': () => ({ deviceAuthorizationService: deviceService }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({
      deriveKey: mock(async () => new Uint8Array(32)),
      getQuote: mock(async () => 'quote'),
      isInTee: () => false,
    }),
    unseal,
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '@tinycloud/sdk-core': (actual) => {
    realActivateSessionWithHost = actual.activateSessionWithHost;
    return { activateSessionWithHost };
  },
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrap,
    isTinyCloudBootstrapComplete,
  }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (and with an isolating query) so the route
  // binds the mocked database, TEE, host activation, and device service.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?complete-context-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?complete-context-routes-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', currentUser);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: currentUser.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});
const savedRetryDelays = process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS;
afterAll(() => {
  if (savedRetryDelays === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS;
  else process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = savedRetryDelays;
});
beforeEach(() => {
  // The retry of a failed setup (TC-1608) has its own tests; here a failed mock must not call back later.
  process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = 'off';
  delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  resetContexts?.();
  currentUser = user;
  keyRecord.keyType = 'MANAGED';
  keyRecord.sealedBlob = 'sealed-blob';
  autoSignEnabled = true;
  bootstrapComplete = false;
  activateSessionWithHost.mockClear();
  activateSessionWithHost.mockImplementation(async () => ({ success: true, status: 200 }));
  ensureTinyCloudBootstrap.mockClear();
  isTinyCloudBootstrapComplete.mockClear();
  prisma.user.findUnique.mockClear();
  unseal.mockClear();
});
async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function prepare(extra: Record<string, unknown> = {}) {
  const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host, ...extra });
  expect(prepared.status).toBe(200);
  return prepared.body;
}

function skipAgents() {
  activateSessionWithHost.mockImplementation(async () => ({
    success: true,
    skipped: [`tinycloud:pkh:eip155:1:${account.address}:agents`],
  }) as any);
}

async function managedApproval(reqHost: string, extra: Record<string, unknown> = {}) {
  const prepared = await prepare({ prefix: 'agents', host: reqHost, ...extra });
  return post('/', {
    keyId: keyRecord.id,
    jwk,
    host: reqHost,
    prepared: prepared.prepared,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
    protocolVersion: 1,
  });
}

async function legacyApproval(reqHost: string) {
  return post('/', { keyId: keyRecord.id, jwk, host: reqHost, prefix: 'agents' });
}

describe('TC-943 prod host pair (pre-merge)', () => {
  const savedEnv = {
    NODE_ENV: process.env.NODE_ENV,
    TEE_MODE: process.env.TEE_MODE,
    TINYCLOUD_BOOTSTRAP_HOST: process.env.TINYCLOUD_BOOTSTRAP_HOST,
  };
  const requestHosts = [
    'https://tee.node.tinycloud.xyz',
    'https://node.tinycloud.xyz',
    'https://tee.node.tinycloud.xyz/',
    'HTTPS://TEE.NODE.TINYCLOUD.XYZ',
  ];
  const untrustedHosts = [
    'https://evil.node.tinycloud.xyz',
    'https://node.tinycloud.xyz.evil.com',
    'http://node.tinycloud.xyz',
    'http://tee.node.tinycloud.xyz',
    'https://node.tinycloud.xyz:8443',
    'https://node.tinycloud.xyz:443',
    'https://user@node.tinycloud.xyz',
    'https://node.tinycloud.xyz/path',
    'https://tee.node.tinycloud.xyz.',
    'https://xn--nde-sna.tinycloud.xyz',
    'https://node.tinyclοud.xyz',
    'not a url',
  ];

  beforeEach(() => {
    delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
    process.env.NODE_ENV = 'production';
    process.env.TEE_MODE = 'production';
    skipAgents();
  });

  afterEach(() => {
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  function expectOnboarding(result: Awaited<ReturnType<typeof post>>, reqHost: string) {
    expect(result.status).toBe(200);
    expect(result.body.hostActivated).toBe(true);
    // Keep readiness and the bootstrap call count together in regression output.
    expect({
      spaceReady: result.body.spaceReady,
      bootstrapCalls: ensureTinyCloudBootstrap.mock.calls.length,
    }).toEqual({ spaceReady: true, bootstrapCalls: 1 });
    expect(result.body.spaceError).toBeUndefined();
    expect(activateSessionWithHost.mock.calls[0]![0]).toBe(reqHost);
    expect(ensureTinyCloudBootstrap).toHaveBeenCalledTimes(1);
    expect(ensureTinyCloudBootstrap).toHaveBeenCalledWith(expect.objectContaining({
      host: 'https://node.tinycloud.xyz',
      chainId: 1,
    }));
  }

  function expectNoOnboarding(result: Awaited<ReturnType<typeof post>>) {
    expect(result.status).toBe(200);
    expect(result.body.hostActivated).toBe(false);
    expect(result.body.spaceReady).toBeNull();
    expect(result.body.spaceError).toBeUndefined();
    expect(ensureTinyCloudBootstrap).not.toHaveBeenCalled();
    expect(activateSessionWithHost).not.toHaveBeenCalled();
    expect(unseal).toHaveBeenCalledTimes(1);
  }

  for (const reqHost of requestHosts) {
    test(`/ versioned finishes onboarding for ${reqHost} keyed by the configured host`, async () => {
      expectOnboarding(await managedApproval(reqHost), reqHost);
    });
  }

  for (const reqHost of requestHosts.slice(0, 2)) {
    test(`/ legacy finishes onboarding for ${reqHost} keyed by the configured host`, async () => {
      expectOnboarding(await legacyApproval(reqHost), reqHost);
    });
  }

  for (const reqHost of requestHosts) {
    test(`/prepare discloses setup for ${reqHost} and checks completion under the configured host`, async () => {
      const result = await prepare({ prefix: 'agents', host: reqHost });
      expect(result.host).toBe(reqHost);
      expect(result.spaceSetup).toEqual({ space: 'agents', plan: 'setup' });
      expect(result.spaceSetup).not.toHaveProperty('bootstrapHost');
      expect(isTinyCloudBootstrapComplete).toHaveBeenCalledWith(expect.anything(), {
        keyId: 'key_1', chainId: 1, host: 'https://node.tinycloud.xyz',
      });
    });
  }

  test('/prepare honours completion stored under the configured host for an alias', async () => {
    bootstrapComplete = true;
    expect((await prepare({ prefix: 'agents', host: requestHosts[0] })).spaceSetup).toBeNull();
    expect(isTinyCloudBootstrapComplete).toHaveBeenCalledWith(expect.anything(), {
      keyId: 'key_1', chainId: 1, host: 'https://node.tinycloud.xyz',
    });
  });

  for (const reqHost of untrustedHosts) {
    test(`/ versioned does not onboard ${reqHost}`, async () => {
      expectNoOnboarding(await managedApproval(reqHost));
    });

    test(`/prepare omits setup for ${reqHost}`, async () => {
      expect((await prepare({ prefix: 'agents', host: reqHost })).spaceSetup).toBeNull();
      expect(isTinyCloudBootstrapComplete).not.toHaveBeenCalled();
      expect(prisma.user.findUnique).not.toHaveBeenCalled();
    });
  }

  for (const reqHost of ['https://evil.node.tinycloud.xyz', 'http://tee.node.tinycloud.xyz']) {
    test(`/ legacy does not onboard ${reqHost}`, async () => {
      expectNoOnboarding(await legacyApproval(reqHost));
    });
  }

  test('/prepare rejects an empty host', async () => {
    expect((await post('/prepare', { keyId: keyRecord.id, jwk, prefix: 'agents', host: '' })).status).toBe(400);
    expect(isTinyCloudBootstrapComplete).not.toHaveBeenCalled();
  });
});

describe('TC-943 local dev host stays exact', () => {
  const savedEnv = {
    NODE_ENV: process.env.NODE_ENV,
    TINYCLOUD_BOOTSTRAP_HOST: process.env.TINYCLOUD_BOOTSTRAP_HOST,
  };
  const localHost = 'http://127.0.0.1:49152';

  beforeEach(() => {
    process.env.NODE_ENV = 'test';
    process.env.TINYCLOUD_BOOTSTRAP_HOST = localHost;
    skipAgents();
  });

  afterEach(() => {
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  test('/prepare does not substitute a prod alias for the local node', async () => {
    expect((await prepare({ prefix: 'agents', host: 'https://tee.node.tinycloud.xyz' })).spaceSetup).toBeNull();
    expect(isTinyCloudBootstrapComplete).not.toHaveBeenCalled();
  });

  test('/ versioned does not onboard a prod alias with local config', async () => {
    const result = await managedApproval('https://tee.node.tinycloud.xyz');
    expect(result.status).toBe(200);
    expect(result.body.spaceReady).toBe(false);
    expect(ensureTinyCloudBootstrap).not.toHaveBeenCalled();
  });

  test('/prepare preserves setup for the exact local host', async () => {
    expect((await prepare({ prefix: 'agents', host: localHost })).spaceSetup).toEqual({ space: 'agents', plan: 'setup' });
    expect(isTinyCloudBootstrapComplete).toHaveBeenCalledWith(expect.anything(), {
      keyId: 'key_1', chainId: 1, host: localHost,
    });
  });
});

describe('/prepare space setup disclosure', () => {
  test('discloses setup for a managed key with auto-sign enabled', async () => {
    expect((await prepare({ prefix: 'agents' })).spaceSetup).toEqual({
      space: 'agents',
      plan: 'setup',
    });
  });

  test('reports when auto-sign is disabled', async () => {
    autoSignEnabled = false;
    expect((await prepare({ prefix: 'agents' })).spaceSetup).toEqual({
      space: 'agents',
      plan: 'auto-sign-off',
    });
  });

  test('reports external wallet setup behavior', async () => {
    keyRecord.keyType = 'EXTERNAL';
    expect((await prepare({ prefix: 'agents' })).spaceSetup).toEqual({
      space: 'agents',
      plan: 'external-wallet',
    });
  });

  test('omits setup already completed', async () => {
    bootstrapComplete = true;
    expect((await prepare({ prefix: 'agents' })).spaceSetup).toBeNull();
  });

  test('omits non-canonical spaces', async () => {
    expect((await prepare({ prefix: 'not-a-bootstrap-space' })).spaceSetup).toBeNull();
  });

  test('omits a host other than the trusted bootstrap host', async () => {
    expect((await prepare({ prefix: 'agents', host: 'https://untrusted.example' })).spaceSetup).toBeNull();
  });
  test('omits the setup promise when bootstrap on sign is switched off', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';
    try {
      expect((await prepare({ prefix: 'agents' })).spaceSetup).toBeNull();
    } finally {
      delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
    }
  });

});

/** The versioned `/complete` body the web sends, signed by `signer`. */
async function completeBody(prepared: Record<string, any>, siwe: string = prepared.prepared.siwe, signer = account) {
  return {
    prepared: { ...prepared.prepared, siwe },
    signature: await signer.signMessage({ message: siwe }),
    host,
    jwk,
    edited: false,
    protocolVersion: 1,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
  };
}

test('TC-959 correlates real HTTP completion and SDK node activation without changing signed authority', async () => {
  const received: Array<{ requestId: string | null; authorization: string | null }> = [];
  const node = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch(request) {
      received.push({ requestId: request.headers.get('X-Request-Id'), authorization: request.headers.get('Authorization') });
      return Response.json({ activated: [], skipped: [] });
    },
  });
  const nodeOrigin = `http://127.0.0.1:${node.port}`;
  const previousHost = process.env.TINYCLOUD_URL;
  process.env.TINYCLOUD_URL = nodeOrigin;
  activateSessionWithHost.mockImplementation(realActivateSessionWithHost);
  const app = new Hono<ApiEnv>();
  app.use('*', requestLogger);
  app.route('/api/delegate', router);
  app.onError(apiErrorHandler);
  const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: app.fetch });
  const incoming = [
    'owner-canary@example.test Bearer token-canary',
    undefined,
    'A3B54A8D-9927-4C01-9A2E-5F4EC31E90B2',
    '64E09578-4CA5-7D12-B172-2EF8762D04CB',
  ];
  try {
    const prepared = await Promise.all(incoming.map(() => prepare({ host: nodeOrigin, prefix: 'tc959' })));
    const completed = await Promise.all(prepared.map(async (preparation, index) => {
      const requestId = incoming[index];
      const body = { ...await completeBody(preparation), host: nodeOrigin };
      const response = await fetch(`http://127.0.0.1:${server.port}/api/delegate/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(requestId ? { 'X-Request-Id': requestId } : {}) },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
      const result = await response.json() as Record<string, any>;
      expect(result.hostActivated).toBe(true);
      const correlationId = response.headers.get('X-Request-Id');
      if (index >= 2) expect(correlationId).toBe(requestId!.toLowerCase());
      else expect(correlationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      expect(result.siwe).toBe(body.prepared.siwe);
      expect(result.signature).toBe(body.signature);
      const edge = received.find((entry) => entry.authorization === result.delegationHeader.Authorization);
      expect(edge?.requestId).toBe(correlationId);
      expect(correlationId).not.toBe(body.authorizationContextToken);
      return correlationId;
    }));
    expect(new Set(completed).size).toBe(incoming.length);
    const errorResponse = await fetch(`http://127.0.0.1:${server.port}/api/delegate/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Request-Id': '34db1e5b-6a32-4f70-9611-fc1e1f737975' },
      body: '{',
    });
    expect(errorResponse.status).toBe(500);
    expect(errorResponse.headers.get('X-Request-Id')).toBe('34db1e5b-6a32-4f70-9611-fc1e1f737975');
  } finally {
    server.stop(true);
    node.stop(true);
    if (previousHost === undefined) delete process.env.TINYCLOUD_URL;
    else process.env.TINYCLOUD_URL = previousHost;
  }
});

/** A fresh device transaction for the test session key and host. */
async function startDeviceTransaction() {
  const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
  const started = await deviceService.start({
    deviceSecretHash: digest(`secret-${Math.random()}`),
    codeChallenge: digest(`verifier-${Math.random()}`),
    sessionDid: sessionDidForPublicJwk(jwk),
    publicJwk: jwk,
    relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
    permissions: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }],
    nodeOrigin: host,
    shareOrigin: 'https://share.tinycloud.xyz',
    delegationTtlSeconds: 60,
  }, `198.51.100.${Math.floor(Math.random() * 250)}`);
  return started.transactionId;
}

const space = `tinycloud:pkh:eip155:1:${account.address}:secrets`;
const kvGet = { service: 'tinycloud.kv', space, path: 'vault/secrets/TOKEN', actions: ['tinycloud.kv/get'] };
const capabilitiesRead = { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] };
const requested = [kvGet, capabilitiesRead];
// A valid session-key verificationMethod that is not the prepared one.
const otherVerificationMethod = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';

interface RefusalCase {
  name: string;
  /** Extra `/prepare` fields; also echoed into the valid completion. */
  prepare?: Record<string, unknown>;
  refuse: (prepared: Record<string, any>) => Promise<Record<string, unknown>>;
  code?: string;
  error?: string;
}

const refusals: RefusalCase[] = [
  {
    name: 'a changed host',
    refuse: async (p) => ({ ...(await completeBody(p)), host: 'https://other-node.example' }),
    code: 'host-mismatch',
  },
  {
    name: 'a correctly signed replacement SIWE address',
    refuse: async (p) => completeBody(p, p.prepared.siwe.replace(account.address, other.address), other),
    code: 'key-mismatch',
  },
  {
    name: 'a missing signed expiry',
    refuse: async (p) => completeBody(p, p.prepared.siwe.replace(/^Expiration Time: .*\n/m, '')),
    code: 'missing_expiration_time',
    error: 'The signed SIWE must include a valid Expiration Time',
  },
  {
    name: 'a bad signature',
    refuse: async (p) => completeBody(p, p.prepared.siwe, other),
    code: 'signature-mismatch',
  },
  {
    name: 'another signed-in user',
    refuse: async (p) => {
      currentUser = otherUser;
      return completeBody(p);
    },
    code: 'user-mismatch',
  },
  {
    name: 'another session key',
    refuse: async (p) => ({ ...(await completeBody(p)), jwk: otherJwk }),
    code: 'jwk-mismatch',
  },
  {
    name: 'another space',
    refuse: async (p) => {
      const body = await completeBody(p);
      return { ...body, prepared: { ...body.prepared, spaceId: `${p.prepared.spaceId}-other` } };
    },
    code: 'space-mismatch',
  },
  {
    name: 'an altered immutable SIWE field',
    refuse: async (p) => completeBody(p, p.prepared.siwe.replace(/^Nonce: (.*)$/m, 'Nonce: $1x')),
    code: 'immutable-fields-changed',
  },
  {
    name: 'another request baseline',
    prepare: { permissions: requested },
    refuse: async (p) => ({
      ...(await completeBody(p)),
      permissions: [{ ...kvGet, actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] }, capabilitiesRead],
    }),
    code: 'baseline-digest-mismatch',
  },
];

describe('versioned /complete validates every binding before consuming the context', () => {
  test('external wallet activation skips the space without attempting onboarding', async () => {
    keyRecord.keyType = 'EXTERNAL';
    keyRecord.sealedBlob = null;
    activateSessionWithHost.mockImplementation(async () => ({
      success: true,
      skipped: [`tinycloud:pkh:eip155:1:${account.address}:agents`],
    }) as any);
    const prepared = await prepare({ prefix: 'agents' });
    const result = await post('/complete', await completeBody(prepared));
    expect(result.status).toBe(200);
    expect(result.body.spaceReady).toBe(false);
    expect(ensureTinyCloudBootstrap).not.toHaveBeenCalled();
  });

  for (const refusal of refusals) {
    test(`refuses ${refusal.name} and leaves the context usable`, async () => {
      const prepared = await prepare(refusal.prepare);
      const refused = await post('/complete', await refusal.refuse(prepared));
      expect(refused.status).toBe(400);
      if (refusal.code) expect(refused.body.code).toBe(refusal.code);
      if (refusal.error) expect(refused.body.error).toBe(refusal.error);
      expect(refused.body.delegationHeader).toBeUndefined();
      expect(activateSessionWithHost).not.toHaveBeenCalled();

      currentUser = user;
      const ok = await post('/complete', { ...(await completeBody(prepared)), ...refusal.prepare });
      expect(ok.status).toBe(200);
      expect(ok.body.delegationHeader).toBeDefined();
      expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
    });
  }

  test('an expired versioned context reports context-expired without activation', async () => {
    const prepared = await prepare();
    const body = await completeBody(prepared);
    setSystemTime(new Date(Date.now() + 6 * 60 * 1000));
    try {
      const refused = await post('/complete', body);
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe('context-expired');
      expect(activateSessionWithHost).not.toHaveBeenCalled();
    } finally {
      setSystemTime();
    }
  });

  test('refuses a device-window violation and leaves the context usable', async () => {
    // An ordinary 90-day prepare completed under a 60-second device
    // transaction: only the device guard refuses it.
    const prepared = await prepare({ expiry: '90d' });
    const deviceTransactionId = await startDeviceTransaction();
    const refused = await post('/complete', { ...(await completeBody(prepared)), deviceTransactionId });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('delegation lifetime exceeds the device request');
    expect(activateSessionWithHost).not.toHaveBeenCalled();

    const ok = await post('/complete', await completeBody(prepared));
    expect(ok.status).toBe(200);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('a successful completion consumes the context and a replay is refused', async () => {
    const prepared = await prepare();
    const body = await completeBody(prepared);
    expect((await post('/complete', body)).status).toBe(200);
    const replay = await post('/complete', body);
    expect(replay.status).toBe(400);
    expect(replay.body.code).toBe('context-not-found');
    expect(replay.body.delegationHeader).toBeUndefined();
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });
  test('reports unknown readiness when host activation fails', async () => {
    activateSessionWithHost.mockImplementationOnce(async () => ({
      success: false,
      status: 502,
      error: 'bad gateway',
    }));
    const result = await post('/complete', await completeBody(await prepare({ prefix: 'agents' })));
    expect(result.status).toBe(200);
    expect(result.body.hostActivated).toBe(false);
    expect(result.body.spaceReady).toBeNull();
  });


  test('of two concurrent completions of one context exactly one succeeds', async () => {
    const prepared = await prepare();
    const body = await completeBody(prepared);
    const results = await Promise.all([post('/complete', body), post('/complete', body)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
    expect(results.find((r) => r.status === 400)?.body.code).toBe('context-not-found');
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  const malformed: Array<[string, (p: Record<string, any>) => Record<string, unknown>]> = [
    ['another verificationMethod', () => ({ verificationMethod: otherVerificationMethod })],
    ['a null verificationMethod', () => ({ verificationMethod: null })],
    // `String([spaceId])` equals the bound space, so only a strict check
    // keeps the array away from WASM.
    ['a spaceId wrapped in an array', (p) => ({ spaceId: [p.prepared.spaceId] })],
  ];
  for (const [name, fields] of malformed) {
    test(`refuses ${name} in the prepared block, and a corrected retry succeeds once`, async () => {
      const prepared = await prepare();
      const body = await completeBody(prepared);
      const refused = await post('/complete', { ...body, prepared: { ...body.prepared, ...fields(prepared) } });
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe('prepared_metadata_mismatch');
      expect(activateSessionWithHost).not.toHaveBeenCalled();

      const ok = await post('/complete', body);
      expect(ok.status).toBe(200);
      expect(ok.body.verificationMethod).toBe(/^URI: (.+)$/m.exec(prepared.prepared.siwe)?.[1]);
      expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
      expect((await post('/complete', body)).status).toBe(400);
    });
  }
});

describe('managed approval checks everything caller-controlled before consuming the context', () => {
  async function approval(extra: Record<string, unknown> = {}) {
    const prepared = await prepare(extra);
    return {
      keyId: keyRecord.id,
      jwk,
      host,
      prepared: prepared.prepared,
      authorizationContextToken: prepared.authorizationContext.token,
      selectedActionIds: prepared.selectedActionKeys,
      protocolVersion: 1,
    };
  }

  test('an expired managed context reports context-expired before signing', async () => {
    const valid = await approval();
    setSystemTime(new Date(Date.now() + 6 * 60 * 1000));
    try {
      const refused = await post('/', valid);
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe('context-expired');
      expect(unseal).not.toHaveBeenCalled();
    } finally {
      setSystemTime();
    }
  });

  test('refuses a device-window violation and leaves the context usable', async () => {
    const valid = await approval({ expiry: '90d' });
    const deviceTransactionId = await startDeviceTransaction();
    const refused = await post('/', { ...valid, deviceTransactionId });
    expect(refused.status).toBe(400);
    expect(refused.body.delegationHeader).toBeUndefined();
    expect(unseal).not.toHaveBeenCalled();

    const ok = await post('/', valid);
    expect(ok.status).toBe(200);
    expect(ok.body.delegationHeader).toBeDefined();
    const replay = await post('/', valid);
    expect(replay.status).toBe(400);
    expect(replay.body.code).toBe('context-not-found');
    expect(unseal).toHaveBeenCalledTimes(1);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('does not claim readiness or onboard when host activation fails', async () => {
    activateSessionWithHost.mockImplementationOnce(async () => ({
      success: false,
      status: 502,
      error: 'bad gateway',
    }));
    const approved = await post('/', await approval({ prefix: 'agents' }));
    expect(approved.status).toBe(200);
    expect(approved.body.hostActivated).toBe(false);
    expect(approved.body.spaceReady).toBeNull();
    expect(approved.body.spaceError).toBeUndefined();
    expect(ensureTinyCloudBootstrap).not.toHaveBeenCalled();
  });

  test('does not claim readiness or onboard when host activation throws', async () => {
    activateSessionWithHost.mockImplementationOnce(async () => {
      throw new Error('host unreachable');
    });
    const approved = await post('/', await approval({ prefix: 'agents' }));
    expect(approved.status).toBe(200);
    expect(approved.body.hostActivated).toBe(false);
    expect(approved.body.spaceReady).toBeNull();
    expect(approved.body.spaceError).toBeUndefined();
    expect(ensureTinyCloudBootstrap).not.toHaveBeenCalled();
  });

  test('finishes onboarding when activation skips a canonical agents space', async () => {
    activateSessionWithHost.mockImplementation(async () => ({
      success: true,
      skipped: [`tinycloud:pkh:eip155:1:${account.address}:agents`],
    }) as any);
    const prepared = await prepare({ prefix: 'agents' });
    const approved = await post('/', {
      keyId: keyRecord.id,
      jwk,
      host,
      prepared: prepared.prepared,
      authorizationContextToken: prepared.authorizationContext.token,
      selectedActionIds: prepared.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(approved.status).toBe(200);
    expect(approved.body.spaceReady).toBe(true);
    expect(approved.body.delegationHeader?.Authorization).toBeString();
    expect(ensureTinyCloudBootstrap).toHaveBeenCalledTimes(1);
  });

  test('does not onboard when auto-sign is disabled and reports bootstrap failure', async () => {
    autoSignEnabled = false;
    activateSessionWithHost.mockImplementation(async () => ({
      success: true,
      skipped: [`tinycloud:pkh:eip155:1:${account.address}:agents`],
    }) as any);
    const prepared = await prepare({ prefix: 'agents' });
    const approved = await post('/', {
      keyId: keyRecord.id,
      jwk,
      host,
      prepared: prepared.prepared,
      authorizationContextToken: prepared.authorizationContext.token,
      selectedActionIds: prepared.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(approved.status).toBe(200);
    expect(approved.body.spaceReady).toBe(false);
    expect(ensureTinyCloudBootstrap).not.toHaveBeenCalled();

    autoSignEnabled = true;
    ensureTinyCloudBootstrap.mockImplementationOnce(async () => ({
      status: 'failed', errorCode: 'tinycloud_bootstrap_failed', errorMessage: 'seed failed',
    }) as any);
    const retry = await prepare({ prefix: 'agents' });
    const failed = await post('/', {
      keyId: keyRecord.id,
      jwk,
      host,
      prepared: retry.prepared,
      authorizationContextToken: retry.authorizationContext.token,
      selectedActionIds: retry.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(failed.status).toBe(200);
    expect(failed.body.spaceReady).toBe(false);
    expect(failed.body.spaceError).toContain('seed failed');
  });

  const malformed: Array<[string, Record<string, unknown>]> = [
    ['a null spaceId', { spaceId: null }],
    ['another spaceId', { spaceId: 'tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000000:default' }],
    ['a null verificationMethod', { verificationMethod: null }],
    ['another verificationMethod', { verificationMethod: otherVerificationMethod }],
  ];
  for (const [name, fields] of malformed) {
    test(`refuses ${name} in the prepared block before signing, and a corrected retry succeeds once`, async () => {
      const valid = await approval();
      const refused = await post('/', { ...valid, prepared: { ...valid.prepared, ...fields } });
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe('prepared_metadata_mismatch');
      expect(unseal).not.toHaveBeenCalled();
      expect(activateSessionWithHost).not.toHaveBeenCalled();

      const ok = await post('/', valid);
      expect(ok.status).toBe(200);
      expect(ok.body.delegationHeader).toBeDefined();
      expect(ok.body.verificationMethod).toBe(/^URI: (.+)$/m.exec(valid.prepared.siwe)?.[1]);
      expect(unseal).toHaveBeenCalledTimes(1);
      expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
    });
  }
});

// TC-658: `tc secrets list` asks for kv/list alone. capabilities/read is
// required only when the request baseline grants it, so this request is
// approvable and the signed delegation carries exactly what was asked for.
describe('a CLI request without capabilities/read (TC-658)', () => {
  const secretsList = [{
    service: 'tinycloud.kv',
    space: 'secrets',
    path: 'vault/secrets/',
    actions: ['tinycloud.kv/list'],
    skipPrefix: true,
  }];

  test('/complete approves it and signs only kv/list', async () => {
    const prepared = await prepare({ permissions: secretsList });
    expect(prepared.permissions.flatMap((p: any) => p.actions.map((a: any) => a.required))).toEqual([false]);
    const ok = await post('/complete', { ...(await completeBody(prepared)), permissions: secretsList });
    expect(ok.status).toBe(200);
    expect(ok.body.delegationHeader).toBeDefined();
    expect(ok.body.permissions).toEqual([{
      service: 'kv',
      space: prepared.prepared.spaceId,
      path: 'vault/secrets/',
      actions: ['tinycloud.kv/list'],
    }]);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('the managed approval approves it', async () => {
    const prepared = await prepare({ permissions: secretsList });
    const ok = await post('/', {
      keyId: keyRecord.id,
      jwk,
      host,
      permissions: secretsList,
      prepared: prepared.prepared,
      authorizationContextToken: prepared.authorizationContext.token,
      selectedActionIds: prepared.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(ok.status).toBe(200);
    expect(ok.body.delegationHeader).toBeDefined();
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('the subset check against the request still refuses a broadened SIWE', async () => {
    // A SIWE for the default consent set (kv, sql, capabilities) completed
    // against the secrets-list request is not a subset of it.
    const defaults = await prepare();
    const prepared = await prepare({ permissions: secretsList });
    const refused = await post('/complete', {
      ...(await completeBody(prepared, defaults.prepared.siwe)),
      permissions: secretsList,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.delegationHeader).toBeUndefined();
    expect(refused.body.error).toBe('Edited permissions must be a subset of the original delegation request');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});


describe('TC-945 bootstrap budget', () => {
  const savedBudget = process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS;
  const cleanups: Array<() => void> = [];
  beforeEach(() => {
    process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS = '50';
    skipAgents();
  });
  afterEach(async () => {
    if (savedBudget === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS;
    else process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS = savedBudget;
    for (const cleanup of cleanups.splice(0)) cleanup();
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
  function deferredBootstrap() {
    let resolve!: (outcome: any) => void;
    let reject!: (error: Error) => void;
    const promise = new Promise<any>((res, rej) => { resolve = res; reject = rej; });
    // Lets the unmodified, unbounded route finish so failing-first tests clean up.
    const guard = setTimeout(() => resolve({ status: 'complete' }), 1500);
    cleanups.push(() => { clearTimeout(guard); resolve({ status: 'complete' }); });
    return { promise, resolve, reject };
  }
  for (const requestHost of ['https://tee.node.tinycloud.xyz', 'https://node.tinycloud.xyz']) {
    for (const [name, approve] of [['versioned', managedApproval], ['legacy', legacyApproval]] as const) {
      test(`slow bootstrap returns pending for ${name} approval via ${requestHost}`, async () => {
        const work = deferredBootstrap();
        ensureTinyCloudBootstrap.mockImplementationOnce(() => work.promise);
        const start = performance.now();
        const result = await approve(requestHost);
        expect(performance.now() - start).toBeLessThan(1000);
        expect(result.status).toBe(200);
        expect(result.body).toMatchObject({
          hostActivated: true,
          spaceReady: null,
          spacePending: true,
          spaceError: 'tinycloud_requested_space_timeout',
        });
        expect(result.body.delegationHeader?.Authorization).toBeString();
        expect(ensureTinyCloudBootstrap).toHaveBeenCalledWith(expect.objectContaining({ host: 'https://node.tinycloud.xyz' }));
        expect(unseal).toHaveBeenCalledTimes(2);
        work.resolve({ status: 'complete' });
      });
    }
  }
  test('fast bootstrap reports ready without a pending marker', async () => {
    const result = await managedApproval(host);
    expect(result.status).toBe(200);
    expect(result.body.spaceReady).toBe(true);
    expect(result.body).not.toHaveProperty('spacePending');
  });
  test('a lock held by another approval reports pending rather than an error', async () => {
    ensureTinyCloudBootstrap.mockImplementationOnce(async () => ({
      status: 'failed', errorCode: 'tinycloud_bootstrap_in_progress', errorMessage: 'Already in progress.',
    }) as any);
    const result = await managedApproval(host);
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({
      hostActivated: true, spaceReady: null, spacePending: true, spaceError: 'tinycloud_bootstrap_in_progress',
    });
  });
  test('other bootstrap failures keep the error contract without a pending marker', async () => {
    ensureTinyCloudBootstrap.mockImplementationOnce(async () => ({
      status: 'failed', errorCode: 'tinycloud_bootstrap_failed', errorMessage: 'seed failed',
    }) as any);
    const result = await managedApproval(host);
    expect(result.body.spaceReady).toBe(false);
    expect(result.body.spaceError).toContain('seed failed');
    expect(result.body).not.toHaveProperty('spacePending');
  });
  for (const [name, approve] of [['versioned', managedApproval], ['legacy', legacyApproval]] as const) {
    test(`bootstrap rejection before the budget keeps the plain setup error for ${name} approval`, async () => {
      ensureTinyCloudBootstrap.mockImplementationOnce(async () => { throw new Error('database unavailable'); });
      const result = await approve(host);
      expect(result.status).toBe(200);
      expect(result.body).toMatchObject({
        hostActivated: true,
        spaceReady: false,
        spaceError: 'TinyCloud account setup failed: database unavailable.',
      });
      expect(result.body).not.toHaveProperty('spacePending');
    });
  }
  test('rejection after the response is logged once without an unhandled rejection', async () => {
    const work = deferredBootstrap();
    ensureTinyCloudBootstrap.mockImplementationOnce(() => work.promise);
    const unhandled = mock(() => {});
    const output: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => { output.push(String(chunk)); return true; }) as typeof process.stdout.write;
    process.on('unhandledRejection', unhandled);
    try {
      const result = await managedApproval(host);
      expect(result.body).toMatchObject({ spaceReady: null, spacePending: true });
      work.reject(new Error('background database failure'));
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(unhandled).not.toHaveBeenCalled();
      expect(output).toHaveLength(1);
      const line = JSON.parse(output[0]!);
      expect(line).toMatchObject({
        level: 'error',
        event: 'tinycloud_bootstrap_background_failed',
        error_code: 'tinycloud_bootstrap_crashed',
        attempt: 1,
        requested_space_hosted: 'timeout',
        request_id: 'startup',
      });
      expect(Object.keys(line).sort()).toEqual(['attempt', 'duration_ms', 'error_code', 'event', 'level', 'request_id', 'requested_space_hosted', 'ts']);
    } finally { process.off('unhandledRejection', unhandled); process.stdout.write = originalWrite; }
  });
});

// TC-1608: the route hands the setup the space the approval is for and the session it signed, and
// answers as soon as that one space is reported, not when the whole setup ends.
describe('TC-1608 requested space', () => {
  const cleanups: Array<() => void> = [];
  beforeEach(skipAgents);
  afterEach(() => { for (const cleanup of cleanups.splice(0)) cleanup(); });
  const wholeSetup = () => {
    const { promise, resolve } = Promise.withResolvers<{ status: 'complete' }>();
    cleanups.push(() => resolve({ status: 'complete' }));
    return promise;
  };

  for (const [name, approve] of [['versioned', managedApproval], ['legacy', legacyApproval]] as const) {
    test(`${name} approval answers ready once the node confirms the space, while the setup runs on`, async () => {
      ensureTinyCloudBootstrap.mockImplementationOnce((async (input: any) => {
        input.requestedSpace.report({ status: 'hosted' });
        return wholeSetup();
      }) as any);
      const result = await approve(host);
      expect(result.body).toMatchObject({ hostActivated: true, spaceReady: true });
      expect(result.body).not.toHaveProperty('spacePending');
      expect(result.body).not.toHaveProperty('spaceError');
      expect(ensureTinyCloudBootstrap).toHaveBeenCalledTimes(1);
      const [setup] = ensureTinyCloudBootstrap.mock.calls[0] as unknown as [Record<string, any>];
      // The space this approval is for, not yet confirmed by an earlier attempt.
      expect(setup.requestedSpace).toMatchObject({ space: 'agents', alreadyHosted: false });
    });
  }

  test('a space the node did not confirm reports the failure with its code', async () => {
    ensureTinyCloudBootstrap.mockImplementationOnce((async (input: any) => {
      input.requestedSpace.report({
        status: 'failed',
        errorCode: 'tinycloud_bootstrap_space_not_hosted',
        errorMessage: 'TinyCloud node did not host agents after its host delegation: space was skipped',
      });
      return wholeSetup();
    }) as any);
    const result = await managedApproval(host);
    expect(result.body.spaceReady).toBe(false);
    expect(result.body.spaceError).toContain('(tinycloud_bootstrap_space_not_hosted)');
    expect(result.body).not.toHaveProperty('spacePending');
  });

  test('an approval for an already hosted space never starts the setup', async () => {
    activateSessionWithHost.mockImplementation(async () => ({ success: true, skipped: [] }) as any);
    const result = await managedApproval(host);
    expect(result.body.spaceReady).toBe(true);
    expect(ensureTinyCloudBootstrap).not.toHaveBeenCalled();
  });
});
