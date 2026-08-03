import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  BOOTSTRAP_DEFAULT_ONLY_SESSION_REQUEST,
  BOOTSTRAP_SESSION_REQUESTS,
  ACCOUNT_MANIFEST_PERMISSIONS,
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
import type { BootstrapAllowlistEntry } from '@tinycloud/bootstrap';

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

function spaceAbilitiesFromResources(
  resources: readonly {
    service: string;
    space: string;
    path: string;
    actions: readonly string[];
  }[],
  resourceAddress = address,
  resourceChainId = chainId,
) {
  const spaceAbilities: Record<string, Record<string, Record<string, string[]>>> = {};
  for (const resource of resources) {
    const spaceName = bootstrapSpaceName(resource.space);
    const spaceId = bootstrapSpaceId(resourceAddress, resourceChainId, spaceName);
    const shortService = resource.service.startsWith('tinycloud.')
      ? resource.service.slice('tinycloud.'.length)
      : resource.service;
    spaceAbilities[spaceId] ??= {};
    spaceAbilities[spaceId]![shortService] ??= {};
    spaceAbilities[spaceId]![shortService]![resource.path] = [...resource.actions];
  }
  return spaceAbilities;
}

function bootstrapSpaceName(space: string): BootstrapSpaceName {
  switch (space) {
    case 'default':
    case 'applications':
    case 'account':
    case 'secrets':
    case 'public':
      return space;
    default:
      throw new Error(`Unexpected bootstrap resource space: ${space}`);
  }
}

function bootstrapSessionSiweWithResources(
  primarySpace: BootstrapSpaceName,
  resources: readonly {
    service: string;
    space: string;
    path: string;
    actions: readonly string[];
  }[],
  rawAbilities?: Record<string, string[]>,
  resourceAddress = address,
  resourceChainId = chainId,
) {
  const spaceId = bootstrapSpaceId(address, chainId, primarySpace);
  const spaceAbilities = spaceAbilitiesFromResources(
    resources,
    resourceAddress,
    resourceChainId,
  );
  return prepareSession({
    address,
    chainId,
    domain: 'cli.tinycloud.xyz',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    spaceId,
    jwk,
    abilities: spaceAbilities[spaceId] ?? {},
    spaceAbilities,
    ...(rawAbilities === undefined ? {} : { rawAbilities }),
  }).siwe;
}

async function postBootstrapMessage(message: string) {
  const router = await delegateRouter();
  return router.request('/sign', {
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
  test('fails loudly when the resolved bootstrap package lacks the canonical account bundle', () => {
    expect(ACCOUNT_MANIFEST_PERMISSIONS).toBeDefined();
    expect(ACCOUNT_MANIFEST_PERMISSIONS).toHaveLength(6);
  });

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

  test('accepts and rejects the same manually permuted recap entries in every order', () => {
    const defaultSpaceId = bootstrapSpaceId(address, chainId, 'default');
    const accountSpaceId = bootstrapSpaceId(address, chainId, 'account');
    const defaultAnchor = entry('kv', defaultSpaceId, '', ['tinycloud.kv/get']);
    const accountEntries: RecapEntry[] = [
      entry('kv', accountSpaceId, 'applications/', [
        'tinycloud.kv/get',
        'tinycloud.kv/put',
        'tinycloud.kv/list',
      ]),
      entry('kv', accountSpaceId, 'spaces/', [
        'tinycloud.kv/get',
        'tinycloud.kv/put',
        'tinycloud.kv/list',
      ]),
      entry('kv', accountSpaceId, 'system/bootstrap/complete', [
        'tinycloud.kv/get',
        'tinycloud.kv/put',
      ]),
      entry('delegation', accountSpaceId, '', ['tinycloud.delegation/list']),
      entry('sql', accountSpaceId, 'account', [
        'tinycloud.sql/read',
        'tinycloud.sql/write',
        'tinycloud.sql/schema',
      ]),
      entry('capabilities', accountSpaceId, '', ['tinycloud.capabilities/read']),
    ];
    const acceptedOrders: RecapEntry[][] = [
      [...accountEntries, defaultAnchor],
      [defaultAnchor, ...accountEntries],
      [accountEntries[0]!, defaultAnchor, ...accountEntries.slice(1)],
    ];
    const rejectedOrders: RecapEntry[][] = acceptedOrders.map((order) =>
      order.map((recapEntry) =>
        recapEntry.service === 'kv' && recapEntry.path === 'applications/'
          ? { ...recapEntry, actions: [...recapEntry.actions, 'tinycloud.kv/del'] }
          : recapEntry,
      ),
    );

    for (const entries of acceptedOrders) {
      expect(evaluateBootstrapSigningScope({ address, chainId, entries })).toEqual({
        allowed: true,
      });
    }
    for (const entries of rejectedOrders) {
      expect(evaluateBootstrapSigningScope({ address, chainId, entries })).toMatchObject({
        allowed: false,
        code: 'outside_bootstrap_allowlist',
      });
    }
  });

  test('rejects an ambiguous set of otherwise valid bootstrap candidates', () => {
    const ambiguousAllowlist: readonly BootstrapAllowlistEntry[] = [
      {
        kind: 'session',
        service: 'tinycloud.session',
        space: 'default',
        actions: ['siwe'],
        resources: [{
          service: 'tinycloud.kv',
          space: 'default',
          path: '',
          actions: ['tinycloud.kv/get'],
        }],
      },
      {
        kind: 'session',
        service: 'tinycloud.session',
        space: 'default',
        actions: ['siwe'],
        resources: [{
          service: 'tinycloud.kv',
          space: 'default',
          path: '',
          actions: ['tinycloud.kv/get'],
        }],
      },
    ];
    const spaceId = bootstrapSpaceId(address, chainId, 'default');

    expect(evaluateBootstrapSigningScope({
      address,
      chainId,
      entries: [entry('kv', spaceId, '', ['tinycloud.kv/get'])],
    }, ambiguousAllowlist)).toMatchObject({
      allowed: false,
      code: 'outside_bootstrap_allowlist',
      reason: 'Ambiguous bootstrap candidates',
    });
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
  test('POST /api/delegate/sign accepts the widened default SIWE with account entries preceding default', async () => {
    const router = await delegateRouter();
    const resources = BOOTSTRAP_SESSION_REQUESTS.default.resources;
    const message = bootstrapSessionSiweWithResources(
      'default',
      [...resources].sort((left, right) =>
        left.space === 'account' && right.space !== 'account' ? -1 :
          left.space !== 'account' && right.space === 'account' ? 1 : 0,
      ),
    );

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

  test('POST /api/delegate/sign accepts BOOTSTRAP_DEFAULT_ONLY_SESSION_REQUEST', async () => {
    const message = bootstrapSessionSiweWithResources(
      'default',
      BOOTSTRAP_DEFAULT_ONLY_SESSION_REQUEST.resources,
    );

    const response = await postBootstrapMessage(message);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: true,
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
    });
    expect(signedMessages).toEqual([message]);
  });

  test('POST /api/delegate/sign accepts widened default SIWE in reversed and permuted resource orders', async () => {
    const resources = BOOTSTRAP_SESSION_REQUESTS.default.resources;
    const orders = [
      [...resources].reverse(),
      [...resources.slice(2).reverse(), ...resources.slice(0, 2).reverse()],
    ];

    for (const orderedResources of orders) {
      const message = bootstrapSessionSiweWithResources('default', orderedResources);
      const response = await postBootstrapMessage(message);
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toMatchObject({
        approved: true,
        signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
      });
    }
    expect(signedMessages).toHaveLength(2);
  });

  test('POST /api/delegate/sign accepts an account-primary action subset', async () => {
    const resource = BOOTSTRAP_SESSION_REQUESTS.account.resources.find(
      (candidate) => candidate.service === 'tinycloud.capabilities' && candidate.path === '',
    );
    if (!resource) throw new Error('Missing account bootstrap anchor resource');
    const message = bootstrapSessionSiweWithResources('account', [{
      ...resource,
      actions: [resource.actions[0]!],
    }]);

    const response = await postBootstrapMessage(message);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: true,
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
    });
    expect(signedMessages).toEqual([message]);
  });

  test('POST /api/delegate/sign rejects an unanchored default account-marker subset', async () => {
    const marker = BOOTSTRAP_SESSION_REQUESTS.default.resources.find(
      (resource) => resource.space === 'account' && resource.path === 'system/bootstrap/complete',
    );
    if (!marker) throw new Error('Missing widened marker resource');
    const message = bootstrapSessionSiweWithResources('default', [{
      ...marker,
      actions: [marker.actions[0]!],
    }]);

    const response = await postBootstrapMessage(message);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: false,
      needsApproval: true,
      code: 'outside_bootstrap_allowlist',
    });
    expect(signedMessages).toEqual([]);
  });

  test('POST /api/delegate/sign accepts canonical account resources alongside the default anchor', async () => {
    const defaultResource = BOOTSTRAP_SESSION_REQUESTS.default.resources.find(
      (resource) => resource.space === 'default' && resource.path === '',
    );
    const accountResource = BOOTSTRAP_SESSION_REQUESTS.account.resources.find(
      (resource) => resource.service === 'tinycloud.capabilities' && resource.path === '',
    );
    if (!defaultResource || !accountResource) throw new Error('Missing bootstrap test resources');
    const message = bootstrapSessionSiweWithResources('default', [defaultResource, accountResource]);

    const response = await postBootstrapMessage(message);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: true,
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
    });
    expect(signedMessages).toEqual([message]);
  });

  test('POST /api/delegate/sign rejects a default anchor combined with account raw encryption ability', async () => {
    const defaultResource = BOOTSTRAP_SESSION_REQUESTS.default.resources.find(
      (resource) => resource.space === 'default' && resource.path === '',
    );
    if (!defaultResource) throw new Error('Missing default bootstrap anchor resource');
    const rawResource = bootstrapEncryptionNetworkId(address, chainId);
    const message = bootstrapSessionSiweWithResources(
      'default',
      [defaultResource],
      { [rawResource]: ['tinycloud.encryption/network.create'] },
    );

    const response = await postBootstrapMessage(message);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: false,
      needsApproval: true,
      code: 'outside_bootstrap_allowlist',
    });
    expect(signedMessages).toEqual([]);
  });

  test('POST /api/delegate/sign rejects wrong-owner and wrong-chain account resources', async () => {
    const resource = BOOTSTRAP_SESSION_REQUESTS.default.resources.find(
      (candidate) => candidate.space === 'account' && candidate.path === 'applications/',
    );
    if (!resource) throw new Error('Missing account bootstrap resource');
    const otherAddress = '0x0000000000000000000000000000000000000001';
    const wrongResourceIdentities: Array<[`0x${string}`, number]> = [
      [otherAddress, chainId],
      [address, 137],
    ];
    for (const [resourceAddress, resourceChainId] of wrongResourceIdentities) {
      const message = bootstrapSessionSiweWithResources(
        'account',
        [resource],
        undefined,
        resourceAddress,
        resourceChainId,
      );
      const response = await postBootstrapMessage(message);
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toMatchObject({
        approved: false,
        needsApproval: true,
        code: 'outside_bootstrap_allowlist',
      });
    }
    expect(signedMessages).toEqual([]);
  });

  test('POST /api/delegate/sign rejects an extra account action', async () => {
    const marker = BOOTSTRAP_SESSION_REQUESTS.default.resources.find(
      (resource) => resource.space === 'account' && resource.path === 'system/bootstrap/complete',
    );
    if (!marker) throw new Error('Missing widened marker resource');
    const message = bootstrapSessionSiweWithResources('default', [{
      ...marker,
      actions: [...marker.actions, 'tinycloud.kv/del'],
    }]);

    const response = await postBootstrapMessage(message);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: false,
      needsApproval: true,
      code: 'outside_bootstrap_allowlist',
    });
    expect(signedMessages).toEqual([]);
  });

  test.each([
    ['account registry delete', 'tinycloud.kv', 'applications/', (resource: typeof BOOTSTRAP_SESSION_REQUESTS.default.resources[number]) => ({
      ...resource,
      actions: [...resource.actions, 'tinycloud.kv/del'],
    })],
    ['delegation action other than list', 'tinycloud.delegation', '', (resource: typeof BOOTSTRAP_SESSION_REQUESTS.default.resources[number]) => ({
      ...resource,
      actions: ['tinycloud.delegation/revoke'],
    })],
    ['capabilities action other than read', 'tinycloud.capabilities', '', (resource: typeof BOOTSTRAP_SESSION_REQUESTS.default.resources[number]) => ({
      ...resource,
      actions: ['tinycloud.capabilities/write'],
    })],
  ])('POST /api/delegate/sign rejects %s from the canonical account bundle', async (_label, service, path, mutate) => {
    const resource = BOOTSTRAP_SESSION_REQUESTS.default.resources.find(
      (candidate) => candidate.space === 'account' &&
        candidate.service === service &&
        candidate.path === path,
    );
    if (!resource) throw new Error(`Missing canonical account resource for ${_label}`);
    const message = bootstrapSessionSiweWithResources('default', [mutate(resource)]);

    const response = await postBootstrapMessage(message);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      approved: false,
      needsApproval: true,
      code: 'outside_bootstrap_allowlist',
    });
    expect(signedMessages).toEqual([]);
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
