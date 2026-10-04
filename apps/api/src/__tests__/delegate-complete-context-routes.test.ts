// TC-587: `/api/delegate/complete` (and the managed approval) check every
// binding before consuming the single-use authorization context. A refused
// request leaves the pending approval usable; a successful completion
// consumes it exactly once, also under concurrent completions.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const other = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const user = { id: 'user_1', email: 'alice@example.test' };
const otherUser = { id: 'user_2', email: 'mallory@example.test' };
let currentUser = user;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const otherJwk = { kty: 'OKP', crv: 'Ed25519', x: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' };
const host = 'https://node.tinycloud.xyz';
const keyRecord = {
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

const activateSessionWithHost = mock(async () => ({ success: true }));
const deviceService = new DeviceAuthorizationService(new MemoryDeviceAuthorizationStore(), {
  verificationOrigin: 'https://openkey.so',
  encryptionSecret: 'test-device-authorization-secret-is-long-enough',
});

const unseal = mock(async () => privateKey);

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({
    deriveKey: mock(async () => new Uint8Array(32)),
    getQuote: mock(async () => 'quote'),
    isInTee: () => false,
  }),
  unseal,
  createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
  generatePrivateKey: () => privateKey,
  getAddressFromPrivateKey: () => account.address,
}));
mock.module('@tinycloud/sdk-core', () => ({ activateSessionWithHost }));
mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', currentUser);
    c.set('session', { id: 'session_1', userId: currentUser.id, expiresAt: new Date(Date.now() + 60_000) });
    await next();
  }),
}));
mock.module('../routes/device-authorization', () => ({ deviceAuthorizationService: deviceService }));

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

beforeEach(() => {
  resetContexts?.();
  currentUser = user;
  activateSessionWithHost.mockClear();
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
      expect(unseal).toHaveBeenCalledTimes(1);
      expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
    });
  }
});
