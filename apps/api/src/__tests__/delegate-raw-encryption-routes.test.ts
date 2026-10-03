// TC-598: `/delegate` routes accept a raw encryption decrypt grant as part of
// the CLI request, sign it as a top-level ReCap resource, and relay it with
// `space: "encryption"` — for managed keys (POST /) and wallet keys
// (/prepare + /complete). Anything not requested is still refused.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';

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

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({
    deriveKey: mock(async () => new Uint8Array(32)),
    getQuote: mock(async () => 'quote'),
    isInTee: () => false,
  }),
  unseal: mock(async () => walletKey),
  createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
  generatePrivateKey: () => walletKey,
  getAddressFromPrivateKey: () => wallet.address,
}));
mock.module('@tinycloud/sdk-core', () => ({ activateSessionWithHost }));
mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
    await next();
  }),
}));

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (and with an isolating query) so the route
  // binds the mocked database, TEE, and host activation.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?raw-encryption-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?raw-encryption-routes-isolated' as string
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
  resetContexts?.();
  activateSessionWithHost.mockClear();
});

const space = `tinycloud:pkh:eip155:1:${wallet.address}:secrets`;
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address}:default`;
const DECRYPT = 'tinycloud.encryption/decrypt';
const kvGet = { service: 'tinycloud.kv', space, path: 'vault/secrets/TC_FWD_TOKEN', actions: ['tinycloud.kv/get'] };
const decrypt = { service: 'tinycloud.encryption', space: 'encryption', path: network, actions: [DECRYPT] };
const capabilitiesRead = { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] };
const request = [kvGet, decrypt, capabilitiesRead];
const relayedDecrypt = { service: 'encryption', space: 'encryption', path: network, actions: [DECRYPT] };

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** The `/complete` body the web's external-wallet path sends. */
async function walletComplete(prepared: Record<string, any>, permissions: unknown[] = request) {
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

describe('wallet keys: /prepare + /complete', () => {
  test('signs and relays the decrypt grant as a raw network resource', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);
    expect(prepared.body.spaceId).toBe(space);
    expect(prepared.body.prepared.siwe).toContain(`'tinycloud.encryption': 'decrypt' for '${network}'`);

    const res = await walletComplete(prepared.body);
    expect(res.status).toBe(200);
    expect(res.body.permissions).toContainEqual(relayedDecrypt);
    expect(res.body.spaceId).toBe(space);
  });

  test('omits the decrypt grant the owner unchecked', async () => {
    const baseline = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request });
    const actionKeys = (baseline.body.selectedActionKeys as string[]).filter((key) => !key.endsWith(`\0${DECRYPT}`));
    const narrowed = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request, actionKeys });
    expect(narrowed.status).toBe(200);
    expect(narrowed.body.prepared.siwe).not.toContain('urn:tinycloud:encryption:');

    const res = await walletComplete(narrowed.body);
    expect(res.status).toBe(200);
    expect(res.body.permissions.map((grant: { service: string }) => grant.service).sort()).toEqual(['capabilities', 'kv']);
  });

  test('/complete refuses a signed decrypt grant the forwarded request did not include', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request });
    const res = await walletComplete(prepared.body, [kvGet, capabilitiesRead]);
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('subset of the original delegation request');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('/prepare refuses an encryption network another account owns', async () => {
    const foreign = { ...decrypt, path: 'urn:tinycloud:encryption:did:pkh:eip155:1:0x0000000000000000000000000000000000000001:default' };
    const res = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: [kvGet, foreign, capabilitiesRead] });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('invalid_permissions');
  });

  test('/complete refuses forwarded permissions that differ from the prepared request', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request });
    const broader = [{ ...kvGet, actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] }, decrypt, capabilitiesRead];
    const res = await walletComplete(prepared.body, broader);
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('baseline-digest-mismatch');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('/complete refuses a non-string prepared.siwe with 400', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request });
    const res = await post('/complete', {
      prepared: { ...prepared.body.prepared, siwe: 123 },
      signature: '0x00',
      host,
      jwk,
      permissions: request,
    });
    expect(res.status).toBe(400);
  });
});

describe('managed keys: POST /', () => {
  test('the versioned approval signs and relays the raw decrypt grant', async () => {
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);

    const res = await post('/', {
      keyId: managedKey.id,
      jwk,
      host,
      permissions: request,
      prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(res.status).toBe(200);
    expect(res.body.signedMessage).toContain(`'tinycloud.encryption': 'decrypt' for '${network}'`);
    expect(res.body.permissions).toContainEqual(relayedDecrypt);
  });

  test('the versioned approval refuses forwarded permissions that differ from the prepared request', async () => {
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: request });
    const res = await post('/', {
      keyId: managedKey.id,
      jwk,
      host,
      permissions: [kvGet, decrypt, { ...capabilitiesRead }, { ...kvGet, path: 'vault/secrets/OTHER' }],
      prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('baseline-digest-mismatch');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('the legacy approval accepts a raw entry without a space', async () => {
    const { space: _omitted, ...decryptWithoutSpace } = decrypt;
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: [kvGet, decryptWithoutSpace, capabilitiesRead] });
    expect(res.status).toBe(200);
    expect(res.body.permissions).toContainEqual(relayedDecrypt);
  });

  test('the legacy approval refuses a foreign network before signing', async () => {
    const foreign = { ...decrypt, path: `urn:tinycloud:encryption:did:pkh:eip155:10:${wallet.address}:default` };
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: [kvGet, foreign, capabilitiesRead] });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('invalid_permissions');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});
