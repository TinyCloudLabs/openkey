import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  BOOTSTRAP_SESSION_REQUESTS,
  bootstrapEncryptionNetworkId,
  bootstrapSpaceId,
  makePkhSpaceId,
  type BootstrapSpaceName,
} from '@tinycloud/bootstrap';
import {
  evaluateAutoSignPolicy,
  evaluateBootstrapHostScope,
  evaluateBootstrapSigningScope,
  evaluateBootstrapSessionScope,
  type RecapEntry,
} from '../routes/delegate-autosign';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const chainId = 1;
const user = { id: 'user_1', email: 'test@example.com' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'test' };

let autoSignEnabled = true;
let signedMessages: string[] = [];
let keyRecord = {
  id: 'key_1',
  userId: user.id,
  address,
  keyType: 'MANAGED',
  sealedBlob: 'sealed-private-key',
  archivedAt: null,
};

const prisma = {
  user: {
    findUnique: mock(async () => ({ autoSignEnabled })),
  },
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== keyRecord.userId) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.address !== undefined && where.address !== keyRecord.address) return null;
      if (where.keyType !== undefined && where.keyType !== keyRecord.keyType) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
  },
};

const tee = {
  deriveKey: mock(async () => new Uint8Array(32)),
  getQuote: mock(async () => 'quote'),
  isInTee: () => false,
};

mock.module('@openkey/db', () => ({
  createPrismaClient: () => prisma,
}));

mock.module('@openkey/tee', () => ({
  createTeeClient: () => tee,
  unseal: mock(async () => privateKey),
  createWalletFromPrivateKey: (key: string) => {
    const wallet = privateKeyToAccount(key as `0x${string}`);
    return {
      ...wallet,
      signMessage: async (args: { message: string }) => {
        signedMessages.push(args.message);
        return wallet.signMessage(args);
      },
    };
  },
  generatePrivateKey: () => privateKey,
  getAddressFromPrivateKey: () => address,
}));

mock.module('@tinycloud/sdk-core', () => ({
  activateSessionWithHost: mock(async () => ({ success: true })),
}));

mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('session', {
      id: 'session_1',
      userId: user.id,
      expiresAt: new Date(Date.now() + 60_000),
    });
    await next();
  }),
}));

beforeEach(() => {
  autoSignEnabled = true;
  signedMessages = [];
  keyRecord = {
    id: 'key_1',
    userId: user.id,
    address,
    keyType: 'MANAGED',
    sealedBlob: 'sealed-private-key',
    archivedAt: null,
  };
});

function entry(
  service: string,
  space: string,
  path: string,
  actions: string[],
): RecapEntry {
  return { service, space, path, actions };
}

function abilitiesFromBootstrapSession(space: BootstrapSpaceName) {
  const abilities: Record<string, Record<string, string[]>> = {};
  for (const resource of BOOTSTRAP_SESSION_REQUESTS[space].resources) {
    const shortService = resource.service.startsWith('tinycloud.')
      ? resource.service.slice('tinycloud.'.length)
      : resource.service;
    abilities[shortService] ??= {};
    abilities[shortService]![resource.path] = [...resource.actions];
  }
  return abilities;
}

function bootstrapSessionSiwe(space: BootstrapSpaceName) {
  const spaceId = bootstrapSpaceId(address, chainId, space);
  return prepareSession({
    address,
    chainId,
    domain: 'cli.tinycloud.xyz',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    spaceId,
    jwk,
    abilities: abilitiesFromBootstrapSession(space),
  }).siwe;
}

function legacyOpenKeySessionSiwe() {
  const spaceId = makePkhSpaceId(address, chainId, 'openkey');
  return prepareSession({
    address,
    chainId,
    domain: 'cli.tinycloud.xyz',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    spaceId,
    jwk,
    abilities: {
      capabilities: {
        '': ['tinycloud.capabilities/read'],
      },
    },
  }).siwe;
}

async function delegateRouter() {
  return (await import('../routes/delegate')).delegateRouter;
}

describe('evaluateBootstrapSessionScope', () => {
  test('accepts bootstrap session capabilities from the imported allowlist', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'default');

    const decision = evaluateBootstrapSessionScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('capabilities', spaceId, '', ['tinycloud.capabilities/read']),
        entry('kv', spaceId, '', [
          'tinycloud.kv/get',
          'tinycloud.kv/put',
          'tinycloud.kv/del',
          'tinycloud.kv/list',
          'tinycloud.kv/metadata',
        ]),
        entry('sql', spaceId, '', ['tinycloud.sql/read', 'tinycloud.sql/write']),
      ],
    });

    expect(decision).toEqual({ allowed: true });
  });

  test('rejects legacy "/" root paths from pre-2.4.1 bootstrap clients', () => {
    // Old @tinycloud/bootstrap encoded root permissions as path "/", which
    // produced double-slash recap resources the node can never authorize.
    // Denying them here degrades those clients' bootstrap to skipped rather
    // than minting unusable delegations.
    const spaceId = bootstrapSpaceId(address, chainId, 'default');

    const decision = evaluateBootstrapSessionScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('sql', spaceId, '/', ['tinycloud.sql/read', 'tinycloud.sql/write']),
      ],
    });

    expect(decision).toMatchObject({
      allowed: false,
      code: 'outside_bootstrap_allowlist',
    });
  });

  test('accepts the account bootstrap raw encryption capability', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'account');

    const decision = evaluateBootstrapSessionScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('capabilities', spaceId, '', ['tinycloud.capabilities/read']),
        entry('encryption', 'encryption', bootstrapEncryptionNetworkId(address, chainId), [
          'tinycloud.encryption/network.create',
        ]),
      ],
    });

    expect(decision).toEqual({ allowed: true });
  });

  test('rejects capabilities outside the bootstrap allowlist', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'default');

    const decision = evaluateBootstrapSessionScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('sql', spaceId, '/', ['tinycloud.sql/admin']),
      ],
    });

    expect(decision).toMatchObject({
      allowed: false,
      code: 'outside_bootstrap_allowlist',
    });
  });
});

describe('evaluateBootstrapSigningScope', () => {
  test('classifies SDK callback SIWE messages as bootstrap session signing requests', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'default');

    const decision = evaluateBootstrapSigningScope({
      address,
      chainId,
      entries: [
        entry('capabilities', spaceId, '', ['tinycloud.capabilities/read']),
        entry('kv', spaceId, '', ['tinycloud.kv/get']),
      ],
    });

    expect(decision).toEqual({ allowed: true });
  });

  test('classifies SDK callback host messages as bootstrap host signing requests', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'public');

    const decision = evaluateBootstrapSigningScope({
      address,
      chainId,
      entries: [
        entry('space', spaceId, '', ['tinycloud.space/host']),
      ],
    });

    expect(decision).toEqual({ allowed: true });
  });
});

describe('evaluateBootstrapHostScope', () => {
  test('accepts space/host delegations for enshrined spaces', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'public');

    const decision = evaluateBootstrapHostScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('space', spaceId, '', ['tinycloud.space/host']),
      ],
    });

    expect(decision).toEqual({ allowed: true });
  });

  test('rejects host delegations for non-enshrined spaces', () => {
    const spaceId = makePkhSpaceId(address, chainId, 'openkey');

    const decision = evaluateBootstrapHostScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('space', spaceId, '', ['tinycloud.space/host']),
      ],
    });

    expect(decision).toMatchObject({
      allowed: false,
      code: 'outside_bootstrap_allowlist',
    });
  });
});

describe('evaluateAutoSignPolicy', () => {
  test('rejects otherwise allowed bootstrap scopes when Auto-Sign is disabled', () => {
    expect(evaluateAutoSignPolicy(false, { allowed: true })).toEqual({
      allowed: false,
      code: 'auto_sign_disabled',
      reason: 'Auto-Sign is disabled for this account',
    });
  });
});

describe('delegateRouter Auto-Sign integration', () => {
  test('POST /api/delegate/sign accepts the SDK signing body for allowlisted bootstrap messages', async () => {
    const router = await delegateRouter();
    const message = bootstrapSessionSiwe('default');

    const response = await router.request('/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        address,
        chainId,
        message,
        type: 'siwe',
        keyId: keyRecord.id,
      }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: true,
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
    });
    expect(signedMessages).toEqual([message]);
  });

  test('POST /api/delegate/sign returns an SDK-readable rejection when Auto-Sign is disabled', async () => {
    autoSignEnabled = false;
    const router = await delegateRouter();

    const response = await router.request('/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        address,
        chainId,
        message: bootstrapSessionSiwe('default'),
        type: 'siwe',
        keyId: keyRecord.id,
      }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: false,
      needsApproval: true,
      code: 'auto_sign_disabled',
    });
    expect(signedMessages).toEqual([]);
  });

  test('POST /api/delegate/sign gates SDK signing bodies outside the bootstrap allowlist', async () => {
    const router = await delegateRouter();

    const response = await router.request('/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        address,
        chainId,
        message: legacyOpenKeySessionSiwe(),
        type: 'siwe',
        keyId: keyRecord.id,
      }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: false,
      needsApproval: true,
      code: 'outside_bootstrap_allowlist',
    });
    expect(signedMessages).toEqual([]);
  });

  test('POST /api/delegate remains explicit-approval capable when Auto-Sign is disabled outside the bootstrap allowlist', async () => {
    autoSignEnabled = false;
    const router = await delegateRouter();

    const response = await router.request('/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: keyRecord.id,
        jwk,
        host: 'https://node.tinycloud.test',
        prefix: 'openkey',
      }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      address,
      chainId,
      hostActivated: true,
      ownerDid: `did:pkh:eip155:${chainId}:${address}`,
      spaceId: `tinycloud:pkh:eip155:${chainId}:${address}:openkey`,
    });
    expect(signedMessages).toHaveLength(1);
  });
});
