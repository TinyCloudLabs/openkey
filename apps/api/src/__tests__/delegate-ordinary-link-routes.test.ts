// TC-547: ordinary `/delegate` links (no device transaction). The web echoes
// the `/prepare` object to versioned `/complete` for wallet keys; ordinary
// lifetimes are capped; signing routes that cannot enforce a device
// transaction refuse `deviceTransactionId`.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import type { PermissionOption, PermissionActionOption } from '../routes/delegate-session';
import { mockModules, replaceModules } from './mock-module';

const walletKey = '0x1111111111111111111111111111111111111111111111111111111111111111';
const wallet = privateKeyToAccount(walletKey);
const other = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
// An externally held wallet key: OpenKey never sees its private key.
const externalKey = {
  id: 'key_ext',
  userId: user.id,
  address: wallet.address,
  keyType: 'EXTERNAL',
  archivedAt: null,
  sealedBlob: null,
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async () => externalKey),
    findMany: mock(async () => [externalKey]),
    findUnique: mock(async () => externalKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
const unseal = mock(async () => walletKey);
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
    unseal,
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
    '../routes/delegate?ordinary-link-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?ordinary-link-routes-isolated' as string
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
  unseal.mockClear();
});

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** The `/complete` body the web's external-wallet path sends. */
async function webCompleteBody(prepared: { body: Record<string, any> }, signer = wallet) {
  return {
    prepared: prepared.body.prepared,
    signature: await signer.signMessage({ message: prepared.body.prepared.siwe }),
    host,
    jwk,
    edited: false,
    authorizationContextToken: prepared.body.authorizationContext.token,
    selectedActionIds: prepared.body.selectedActionKeys,
  };
}

describe('versioned /complete for wallet keys', () => {
  test('approves the prepared object the web echoes back, bound to the signed SIWE address', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    expect(prepared.status).toBe(200);
    expect(prepared.body.prepared.address).toBeUndefined();

    const res = await post('/complete', await webCompleteBody(prepared));
    expect(res.status).toBe(200);
    expect(res.body.delegationHeader?.Authorization).toBeString();
    expect(res.body.address.toLowerCase()).toBe(wallet.address.toLowerCase());
    expect(res.body.ownerDid.toLowerCase()).toBe(`did:pkh:eip155:1:${wallet.address}`.toLowerCase());
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);

    // The context is single-use.
    const replay = await post('/complete', await webCompleteBody(prepared));
    expect(replay.status).toBe(400);
  });

  test('refuses a prepared.address that disagrees with the signed SIWE', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    const body = await webCompleteBody(prepared);
    const res = await post('/complete', { ...body, prepared: { ...body.prepared, address: other.address } });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('key-mismatch');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('refuses a SIWE prepared for another key under this context', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    const forged = prepared.body.prepared.siwe.replace(wallet.address, other.address);
    const res = await post('/complete', {
      ...(await webCompleteBody(prepared)),
      prepared: { ...prepared.body.prepared, siwe: forged },
      signature: await other.signMessage({ message: forged }),
    });
    expect(res.status).toBe(400);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('refuses a signature from another wallet without consuming the context or activating', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    const wrongWallet = await post('/complete', await webCompleteBody(prepared, other));
    expect(wrongWallet.status).toBe(400);
    expect(wrongWallet.body.code).toBe('signature-mismatch');
    expect(wrongWallet.body.delegationHeader).toBeUndefined();
    const garbage = await post('/complete', { ...(await webCompleteBody(prepared)), signature: '0x1234' });
    expect(garbage.status).toBe(400);
    expect(activateSessionWithHost).not.toHaveBeenCalled();

    // The context is still unused: the right wallet can complete it.
    const ok = await post('/complete', await webCompleteBody(prepared));
    expect(ok.status).toBe(200);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('reports the signed SIWE expiry, ignoring caller-supplied expiry metadata', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, expiry: '1h' });
    const signedExpiry = /^Expiration Time: (.+)$/m.exec(prepared.body.prepared.siwe)?.[1];
    const body = await webCompleteBody(prepared);
    const res = await post('/complete', {
      ...body,
      prepared: { ...body.prepared, expirationTime: '2099-01-01T00:00:00.000Z' },
    });
    expect(res.status).toBe(200);
    expect(signedExpiry).toBeString();
    expect(res.body.expirationTime).toBe(signedExpiry);
    expect(res.body.expiresAt).toBe(signedExpiry);
    expect(res.body.expiry).toBe(signedExpiry);
  });
});

describe('ordinary requester attribution', () => {
  test.each([
    ['https://mcp.tinycloud.xyz', 'mcp.tinycloud.xyz'],
    ['https://personal.example:8443', 'personal.example:8443'],
    ['http://localhost:8787', 'localhost:8787'],
    ['http://127.0.0.1:8787', '127.0.0.1:8787'],
    ['http://[::1]:8787', '[::1]:8787'],
    [undefined, 'cli.tinycloud.xyz'],
  ])('binds %s through preparation, narrowing and wallet completion', async (requesterOrigin, domain) => {
    const input = { keyId: externalKey.id, jwk, host, requesterOrigin };
    const prepared = await post('/prepare', input);
    expect(prepared.status).toBe(200);
    expect(prepared.body.prepared.siwe.split('\n')[0]).toBe(`${domain} wants you to sign in with your Ethereum account:`);
    const removable = prepared.body.permissions.flatMap((permission: PermissionOption) => permission.actions)
      .find((action: PermissionActionOption) => !action.required);
    expect(removable).toBeDefined();
    const selected = prepared.body.selectedActionKeys.filter((key: string) => key !== removable.key);
    const narrowed = await post('/prepare', { ...input, actionKeys: selected });
    expect(narrowed.status).toBe(200);
    expect(narrowed.body.prepared.siwe.split('\n')[0]).toBe(`${domain} wants you to sign in with your Ethereum account:`);
    expect(new Set(narrowed.body.selectedActionKeys)).toEqual(new Set(selected));
    const completed = await post('/complete', await webCompleteBody(narrowed));
    expect(completed.status).toBe(200);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test.each([
    null, false, {}, ['https://mcp.tinycloud.xyz'], '',
    'http://mcp.tinycloud.xyz', 'http://localhost.evil.example:8787',
    'http://127.0.0.1.evil.example:8787', 'http://sub.localhost:8787',
    'http://127.1:8787', 'http://2130706433:8787', 'http://0x7f000001:8787',
    'http://127.0.0.2:8787', 'http://localhost:80', 'http://localhost:8787/',
    'http://user@localhost:8787', 'http://[0:0:0:0:0:0:0:1]:8787',
    'https://mcp.tinycloud.xyz/', 'https://mcp.tinycloud.xyz/path',
    'https://mcp.tinycloud.xyz?x=1', 'https://mcp.tinycloud.xyz#fragment',
    'https://user@mcp.tinycloud.xyz', 'https://MCP.tinycloud.xyz',
    'https://mcp.tinycloud.xyz:443', ' https://mcp.tinycloud.xyz',
    'https://mcp.tinycloud.xyz\n', 'https://*.tinycloud.xyz',
    'https://mcp.tinycloud.xyz\\evil',
  ].map(requesterOrigin => [requesterOrigin]))('rejects invalid or ambiguous requester origin %j', async (requesterOrigin) => {
    const result = await post('/prepare', { keyId: externalKey.id, jwk, host, requesterOrigin });
    expect(result.status).toBe(400);
    expect(result.body.code).toBe('invalid_requester_origin');
    expect(result.body.authorizationContext).toBeUndefined();
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test.each(['deviceTransactionId', 'approvalRequestId'])('cannot override %s identity', async (binding) => {
    const result = await post('/prepare', {
      keyId: externalKey.id, jwk, host, requesterOrigin: 'https://mcp.tinycloud.xyz', [binding]: 'bound-request',
    });
    expect(result.status).toBe(400);
    expect(result.body.code).toBe('requester_origin_unsupported');
    expect(result.body.authorizationContext).toBeUndefined();
  });

  test('cannot override an origin-bound signing request', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host });
    const result = await post('/authorize-sign-prepare', {
      keyId: externalKey.id, jwk, host, siwe: prepared.body.prepared.siwe,
      requestOrigin: 'https://cli.tinycloud.xyz', requesterOrigin: 'https://mcp.tinycloud.xyz',
    });
    expect(result.status).toBe(400);
    expect(result.body.code).toBe('requester_origin_unsupported');
    expect(result.body.authorizationContext).toBeUndefined();
  });

  test('rejects a correctly signed replacement domain without burning the context', async () => {
    const prepared = await post('/prepare', {
      keyId: externalKey.id, jwk, host, requesterOrigin: 'https://mcp.tinycloud.xyz',
    });
    const body = await webCompleteBody(prepared);
    const substituted = body.prepared.siwe.replace('mcp.tinycloud.xyz', 'cli.tinycloud.xyz');
    const refused = await post('/complete', {
      ...body, prepared: { ...body.prepared, siwe: substituted },
      signature: await wallet.signMessage({ message: substituted }),
    });
    expect(refused.status).toBe(400);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
    expect((await post('/complete', body)).status).toBe(200);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });
});

describe('ordinary delegation lifetime', () => {
  test('/prepare caps a requested lifetime at 30 days and keeps shorter ones', async () => {
    const expiresIn = async (expiry: string) => {
      const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, expiry });
      expect(prepared.status).toBe(200);
      const line = /^Expiration Time: (.+)$/m.exec(prepared.body.prepared.siwe)?.[1];
      return Date.parse(line ?? '') - Date.now();
    };
    const day = 24 * 60 * 60 * 1000;
    const capped = await expiresIn('90d');
    expect(capped).toBeLessThanOrEqual(30 * day);
    expect(capped).toBeGreaterThan(30 * day - 60_000);
    const hour = await expiresIn('1h');
    expect(hour).toBeLessThanOrEqual(60 * 60 * 1000);
    expect(hour).toBeGreaterThan(60 * 60 * 1000 - 60_000);
  });
});

describe('signing routes without device enforcement', () => {
  test('/sign and /host refuse deviceTransactionId before signing', async () => {
    const sign = await post('/sign', {
      address: wallet.address,
      chainId: 1,
      message: 'hello',
      type: 'siwe',
      deviceTransactionId: 'unknown-transaction',
    });
    expect(sign.status).toBe(400);
    expect(sign.body).toMatchObject({ approved: false, code: 'device_transaction_unsupported' });

    const hostSign = await post('/host', {
      keyId: externalKey.id,
      peerId: 'peer',
      space: 'default',
      deviceTransactionId: 'unknown-transaction',
    });
    expect(hostSign.status).toBe(400);
    expect(hostSign.body.code).toBe('device_transaction_unsupported');
    expect(unseal).not.toHaveBeenCalled();
  });
});
