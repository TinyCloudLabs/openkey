// TC-598: `/delegate` routes accept a raw encryption decrypt grant as part of
// the CLI request, sign it as a top-level ReCap resource, and relay it with
// `space: "encryption"` — for managed keys (POST /) and wallet keys
// (/prepare + /complete). Anything not requested is still refused.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { verifyMessage } from 'viem';
import { completeSessionSetup, TCWSessionManager } from '@tinycloud/node-sdk-wasm';
import nodeScopeVectors from './fixtures/share-decrypt-node-vectors.json';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
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
// The same grants as `kvReadWrite`, spelled differently: actions reversed, or
// split across entries on the same resource (raw network included).
const KV_PUT = 'tinycloud.kv/put';
const kvReadWrite = [{ ...kvGet, actions: ['tinycloud.kv/get', KV_PUT] }, decrypt, capabilitiesRead];
const reordered = [{ ...kvGet, actions: [KV_PUT, 'tinycloud.kv/get'] }, { ...decrypt, actions: [DECRYPT, DECRYPT] }, capabilitiesRead];
const split = [kvGet, { ...kvGet, actions: [KV_PUT] }, decrypt, { ...decrypt, space: undefined }, capabilitiesRead];

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

  test('/complete accepts forwarded permissions that grant the same actions in another order or split', async () => {
    for (const forwarded of [reordered, split]) {
      const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: kvReadWrite });
      expect(prepared.status).toBe(200);
      const res = await walletComplete(prepared.body, forwarded);
      expect(res.status).toBe(200);
    }
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

  test('the versioned approval accepts forwarded permissions that grant the same actions in another order or split', async () => {
    for (const forwarded of [reordered, split]) {
      const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: kvReadWrite });
      const res = await post('/', {
        keyId: managedKey.id,
        jwk,
        host,
        permissions: forwarded,
        prepared: prepared.body.prepared,
        authorizationContextToken: prepared.body.authorizationContext.token,
        selectedActionIds: prepared.body.selectedActionKeys,
        protocolVersion: 1,
      });
      expect(res.status).toBe(200);
    }
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

describe('exact share decrypt: create, prepare and signing (TC-1424)', () => {
  const shareSpace = `tinycloud:pkh:eip155:1:${wallet.address}:default`;
  const shareResource = `${network}/share/abc123`;
  const sharePermissions = [
    { ...capabilitiesRead, space: shareSpace },
    { ...decrypt, path: shareResource },
  ];

  function recapAtt(siwe: string) {
    const encoded = /^- urn:recap:(.+)$/m.exec(siwe)![1]!;
    return JSON.parse(Buffer.from(encoded, 'base64url').toString()).att;
  }

  async function assertSigned(body: Record<string, any>) {
    expect(await verifyMessage({
      address: wallet.address, message: body.signedMessage, signature: body.signature,
    })).toBe(true);
    expect(recapAtt(body.signedMessage)).toEqual({
      [`${shareSpace}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
      [shareResource]: { [DECRYPT]: [{}] },
    });
    expect(body.permissions).toContainEqual({
      service: 'encryption', space: 'encryption', path: shareResource, actions: [DECRYPT],
    });
  }

  test('external-wallet prepare and complete sign only the exact leaf', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: sharePermissions });
    expect(prepared.status).toBe(200);
    const signed = await walletComplete(prepared.body, sharePermissions);
    expect(signed.status).toBe(200);
    await assertSigned(signed.body);
  });

  test('managed-key versioned approval signs only the exact leaf', async () => {
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: sharePermissions });
    expect(prepared.status).toBe(200);
    const signed = await post('/', {
      keyId: managedKey.id, jwk, host, permissions: sharePermissions,
      prepared: prepared.body.prepared, protocolVersion: 1,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
    });
    expect(signed.status).toBe(200);
    await assertSigned(signed.body);
  });

  test('managed-key create signs the same exact leaf without a prepare round trip', async () => {
    const signed = await post('/', { keyId: managedKey.id, jwk, host, permissions: sharePermissions });
    expect(signed.status).toBe(200);
    await assertSigned(signed.body);
  });

  test('recipient delegation covers exactly its share and never the folder or another share (node v1.25.12)', async () => {
    const recipient = new TCWSessionManager();
    recipient.createSessionKey('recipient');
    const { kty, crv, x } = JSON.parse(recipient.jwk('recipient')!);
    const recipientJwk = { kty, crv, x };
    const recipientDid = recipient.getDID('recipient');
    const recipientPermissions = [
      { service: 'tinycloud.kv', space: shareSpace, path: 'shares/abc123/file.txt', actions: ['tinycloud.kv/get', 'tinycloud.kv/metadata'] },
      sharePermissions[1]!,
    ];
    try {
      const prepared = await post('/prepare', {
        keyId: externalKey.id, jwk: recipientJwk, host, permissions: recipientPermissions,
      });
      expect(prepared.status).toBe(200);
      const signed = await post('/complete', {
        prepared: prepared.body.prepared, host, jwk: recipientJwk, permissions: recipientPermissions,
        signature: await wallet.signMessage({ message: prepared.body.prepared.siwe }),
        authorizationContextToken: prepared.body.authorizationContext.token,
        selectedActionIds: prepared.body.selectedActionKeys,
      });
      expect(signed.status).toBe(200);
      expect(await verifyMessage({
        address: wallet.address, message: signed.body.signedMessage, signature: signed.body.signature,
      })).toBe(true);
      expect(/^URI: (.+)$/m.exec(signed.body.signedMessage)?.[1]).toBe(recipientDid);
      // Rebuild the actual signed delegation, not the relayed permission metadata.
      const delegation = completeSessionSetup({
        ...prepared.body.prepared, signature: signed.body.signature,
      });
      expect(signed.body.delegationHeader).toEqual(delegation.delegationHeader);
      const signedGrants = Object.entries(recapAtt(signed.body.signedMessage));
      expect(signedGrants.filter(([resource]) => !resource.startsWith('urn:tinycloud:encryption:'))).toEqual([
        [`${shareSpace}/kv/shares/abc123/file.txt`, { 'tinycloud.kv/get': [{}], 'tinycloud.kv/metadata': [{}] }],
      ]);
      const encryption = signedGrants
        .filter(([resource]) => resource.startsWith('urn:tinycloud:encryption:'));
      expect(encryption).toHaveLength(1);
      for (const [, actions] of encryption) expect(actions).toEqual({ [DECRYPT]: [{}] });
      // These vectors were executed against the unmodified v1.25.12 Rust
      // EncryptionResource::extends and check_decrypt_scope, not OpenKey's parser.
      // A signed share/ prefix covers share/other and fails this same assertion.
      for (const target of nodeScopeVectors.vectors.filter((row) => row.granted === shareResource)) {
        const covered = encryption.some(([granted]) => {
          const vector = nodeScopeVectors.vectors.find((row) =>
            row.granted === granted && row.requested === target.requested &&
            row.bodyKeyPath === target.bodyKeyPath && row.factsKeyPath === target.factsKeyPath);
          expect(vector, `Missing node vector for signed resource ${granted}`).toBeDefined();
          return vector!.covers && vector!.decryptScope;
        });
        const isThisShare = target.requested === shareResource &&
          target.bodyKeyPath === 'share/abc123' && target.factsKeyPath === 'share/abc123';
        expect(covered, `Recipient reach: ${target.requested}`).toBe(isThisShare);
      }
    } finally {
      recipient.free();
    }
  });

  test('neither create nor prepare accepts a prefix or an adjacent scope', async () => {
    for (const path of [`${network}/share/`, `${shareResource}/`, `${shareResource}/child`, `${shareResource}%2Fchild`, `${network}/apps/demo/key`]) {
      for (const route of ['/', '/prepare']) {
        const result = await post(route, {
          keyId: managedKey.id, jwk, host,
          permissions: [sharePermissions[0], { ...sharePermissions[1], path }],
        });
        expect(result.status).toBe(400);
        expect(result.body.code).toBe('invalid_permissions');
      }
    }
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('a signed leaf cannot complete under another forwarded leaf', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: sharePermissions });
    expect(prepared.status).toBe(200);
    const result = await walletComplete(prepared.body, [
      sharePermissions[0]!, { ...sharePermissions[1]!, path: `${network}/share/other` },
    ]);
    expect(result.status).toBe(400);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});
