// TC-1781: decrypt lifetime cap on non-device `/delegate` transports, behind
// DECRYPT_LIFETIME_ENFORCE_NON_DEVICE. Flag OFF keeps existing behaviour. Flag
// ON refuses a decrypt entry that is not alone or has no explicit lifetime of
// at most one hour, before any signing or side effect.

import { afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { decryptRefusalForSignedSiwe } from '../routes/delegate-session';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { mockModules, replaceModules } from './mock-module';

const walletKey = '0x1111111111111111111111111111111111111111111111111111111111111111';
const wallet = privateKeyToAccount(walletKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const keyBase = { userId: user.id, address: wallet.address, archivedAt: null, sealingContext: null };
const managedKey = { ...keyBase, id: 'key_managed', keyType: 'MANAGED', sealedBlob: 'sealed-blob' };
const externalKey = { ...keyBase, id: 'key_ext', keyType: 'EXTERNAL', sealedBlob: null };
const keys = [managedKey, externalKey];

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id?: string } }) => keys.find((key) => key.id === where.id) ?? null),
    findMany: mock(async () => keys),
    findUnique: mock(async () => managedKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
const activateSessionWithHost = mock(async () => ({ success: true }));

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
    unseal: mock(async () => walletKey),
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => walletKey,
    getAddressFromPrivateKey: () => wallet.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;
let refusalFor: typeof decryptRefusalForSignedSiwe;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (with an isolating query) so the route binds
  // the mocked database, TEE, and host activation.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?decrypt-lifetime-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?decrypt-lifetime-routes-isolated' as string
  ));
  ({ decryptRefusalForSignedSiwe: refusalFor } = await import(
    '../routes/delegate-session?decrypt-lifetime-routes-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

const FLAG = 'DECRYPT_LIFETIME_ENFORCE_NON_DEVICE';
const REFUSAL = 'a decrypt approval lasts at most one hour';
const SINGLE_SPACE = 'permissions must belong to a single space';
let savedFlag: string | undefined;

function setFlag(value: string | undefined) {
  if (value === undefined) delete process.env[FLAG];
  else process.env[FLAG] = value;
}

beforeEach(() => {
  savedFlag = process.env[FLAG];
  setFlag(undefined);
  resetContexts?.();
  activateSessionWithHost.mockClear();
});

afterEach(() => {
  setFlag(savedFlag);
});

const space = `tinycloud:pkh:eip155:1:${wallet.address}:secrets`;
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address}:default`;
const DECRYPT = 'tinycloud.encryption/decrypt';
const kvGet = { service: 'tinycloud.kv', space, path: 'vault/secrets/TC_FWD_TOKEN', actions: ['tinycloud.kv/get'] };
const decrypt = { service: 'tinycloud.encryption', space: 'encryption', path: network, actions: [DECRYPT] };
const capabilitiesRead = { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] };
// The CLI shape that carries a decrypt grant: decrypt is one entry among others.
const request = [kvGet, decrypt, capabilitiesRead];
const decryptOnly = [decrypt];
// Session-bundle shape: decrypt and network.create in one entry.
const bundledDecrypt = [
  { service: 'tinycloud.encryption', space: 'encryption', path: network, actions: [DECRYPT, 'tinycloud.encryption/network.create'] },
];
const relayedDecrypt = { service: 'encryption', space: 'encryption', path: network, actions: [DECRYPT] };
const noDecrypt = [kvGet, capabilitiesRead];

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** Seconds from now until the Expiration Time of a prepared SIWE message. */
function expiresInSeconds(siwe: string): number {
  const match = siwe.match(/Expiration Time: (.+)/);
  return (Date.parse(match?.[1] ?? '') - Date.now()) / 1000;
}

/** The `/complete` body the web's external-wallet path sends. */
async function walletComplete(prepared: Record<string, any>, permissions: unknown[]) {
  return post('/complete', {
    prepared: prepared.prepared,
    signature: await wallet.signMessage({ message: prepared.prepared.siwe }),
    host,
    jwk,
    edited: prepared.edited,
    permissions,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
  });
}

/** Versioned managed approval for a prepared request. */
async function managedApprove(prepared: Record<string, any>, permissions: unknown[]) {
  return post('/', {
    keyId: managedKey.id,
    jwk,
    host,
    permissions,
    prepared: prepared.prepared,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
    protocolVersion: 1,
  });
}

describe('flag OFF: non-device behaviour unchanged', () => {
  test('legacy approval signs a request carrying a decrypt grant at the 7-day default', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(res.status).toBe(200);
  });

  test('versioned approval signs a request carrying a decrypt grant at the 7-day default', async () => {
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);
    expect(expiresInSeconds(prepared.body.prepared.siwe)).toBeGreaterThan(6 * 24 * 3600);
    const res = await managedApprove(prepared.body, request);
    expect(res.status).toBe(200);
  });

  test('wallet /prepare + /complete relays the decrypt grant at the 7-day default', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);
    const res = await walletComplete(prepared.body, request);
    expect(res.status).toBe(200);
    expect(res.body.permissions).toContainEqual(relayedDecrypt);
  });

  test('a non-canonical flag value leaves the cap off', async () => {
    setFlag('yes');
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(res.status).toBe(200);
  });

  test('a decrypt-only request is rejected by the existing single-space rule, with or without the flag', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });
});

describe('flag ON: refusal before any side effect', () => {
  beforeEach(() => {
    setFlag('true');
  });

  test('legacy approval refuses a decrypt-only grant at the 7-day default with the fixed message', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(res.body.code).toBe('invalid_request');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('legacy approval refuses a decrypt-only grant over one hour', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '61m' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
  });

  // Gap, not acceptance: a lone decrypt entry at one hour passes the cap, but
  // prepareDelegationSession still refuses it as a single-space violation.
  // Reaching the step-up shape through /delegate needs a validator decision.
  test('legacy approval at exactly one hour passes the cap and stops at the single-space rule', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });

  test('legacy approval refuses decrypt beside other entries, even at one hour', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: request, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('legacy approval refuses a decrypt and network.create entry in one bundle at one hour', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: bundledDecrypt, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
  });

  test('legacy approval without decrypt is unchanged at the 7-day default', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: noDecrypt });
    expect(res.status).toBe(200);
  });

  test('/prepare refuses a decrypt-only grant at the 7-day default and returns no prepared session', async () => {
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(res.body.prepared).toBeUndefined();
  });

  test('/prepare refuses a request carrying decrypt beside other entries', async () => {
    const res = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
  });

  test('/prepare without decrypt is unchanged at the 7-day default', async () => {
    const res = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: noDecrypt });
    expect(res.status).toBe(200);
  });

  test('/complete refuses a decrypt grant prepared while the flag was off, before activation', async () => {
    setFlag(undefined);
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);

    setFlag('true');
    const res = await walletComplete(prepared.body, request);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('versioned approval refuses a grant prepared while the flag was off, and the context is not consumed', async () => {
    setFlag(undefined);
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);

    setFlag('true');
    const refused = await managedApprove(prepared.body, request);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe(REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();

    setFlag(undefined);
    const retried = await managedApprove(prepared.body, request);
    expect(retried.status).toBe(200);
  });
});

describe('decryptRefusalForSignedSiwe', () => {
  const siweWith = (resources: string) =>
    [
      'openkey.test wants you to sign in with your Ethereum account:',
      wallet.address,
      '',
      'Authorize',
      '',
      'URI: https://openkey.test',
      'Version: 1',
      'Chain ID: 1',
      'Nonce: abc',
      'Issued At: 2030-01-01T00:00:00.000Z',
      'Expiration Time: 2030-01-01T00:30:00.000Z',
      'Resources:',
      resources,
    ].join('\n');

  test('refuses a recap resource that cannot be parsed while the flag is on', () => {
    setFlag('true');
    expect(refusalFor(siweWith('- urn:recap:!!!not-a-recap!!!'))?.error).toBe(REFUSAL);
  });

  test('passes ordinary text that mentions decrypt but carries no recap', () => {
    setFlag('true');
    expect(refusalFor('Please decrypt the vault for the team.')).toBeNull();
  });

  test('returns null for an unparseable recap while the flag is off', () => {
    setFlag(undefined);
    expect(refusalFor(siweWith('- urn:recap:!!!not-a-recap!!!'))).toBeNull();
  });
});
