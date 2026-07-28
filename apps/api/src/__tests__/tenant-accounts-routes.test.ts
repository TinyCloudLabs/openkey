// Direct HTTP route tests for /v1/accounts and management credential endpoints.
// Uses the REAL tenant-managed-accounts service backed by an in-memory DB mock.
// No production service logic is reimplemented here.
import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { Hono } from 'hono';
import { privateKeyToAccount } from 'viem/accounts';

const now = new Date('2026-07-20T12:00:00.000Z');

const testAccount = {
  id: 'acct-1',
  subjectEmail: 'alice@example.test',
  externalUserId: 'ext-alice',
  state: 'MANAGED',
  custodyEpoch: 1,
  revocationStatus: 'NOT_REQUIRED',
  tenantAccess: 'NOT_REQUIRED',
  createdAt: now,
  updatedAt: now,
  key: { address: '0x1111111111111111111111111111111111111111', userId: null, sealedBlob: 'sealed', sealingContext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ' },
  custodyHead: { custodianType: 'ORGANIZATION' as const, custodianId: 'org-1', epoch: 1, revokedAt: null },
  organizationId: 'org-1',
  ownerUserId: null,
  keyId: 'key-1',
  metadata: null,
  tenantParentDelegationCid: null,
};

const disabledAccount = {
  ...testAccount,
  id: 'acct-disabled',
  subjectEmail: 'disabled@example.test',
  externalUserId: 'ext-disabled',
  state: 'DISABLED',
  custodyHead: { custodianType: 'ORGANIZATION' as const, custodianId: 'org-1', epoch: 1, revokedAt: null },
};

const planEntitlements = {
  id: 'ent-1', organizationId: 'org-1', version: 1, maxApps: 3, maxOrganizationMembers: 10,
  maxManagedAccounts: 100, monthlyActiveManagedUsers: 100, storageBytesPerManagedAccount: 100n,
  requestsPerMinute: 60, maxTenantDelegationTtlSeconds: 3600, maxTenantPolicyVersion: 1,
  webhookDelivery: false, auditRetentionDays: 7, createdAt: now, updatedAt: now,
};

let currentAccounts: typeof testAccount[];

const credential = {
  id: 'cred-1', organizationId: 'org-1', subjectUserId: 'user-1', kind: 'MANAGEMENT' as const,
  secretHash: 'hash', secretPrefix: 'oksk_prefix', name: 'Test', revokedAt: null, createdAt: now, lastUsedAt: null,
};

const prisma = {
  $transaction: mock(async (fn: any, _opts?: any) => fn(prisma)),
  $queryRaw: mock(async () => []),
  managedAccount: {
    findFirst: mock(async ({ where }: any) => {
      const account = currentAccounts.find((a) => a.id === where.id && a.organizationId === where.organizationId);
      return account ?? null;
    }),
    findMany: mock(async ({ where }: any) => {
      return currentAccounts
        .filter((a) => {
          if (where.organizationId && a.organizationId !== where.organizationId) return false;
          if (where.ownerUserId && a.ownerUserId !== where.ownerUserId) return false;
          if (where.state?.in) return where.state.in.includes(a.state);
          if (where.state) return a.state === where.state;
          return true;
        })
        .map((a) => ({
          ...a,
          organization: { name: 'Test Org' },
          ejectRevocationReceipts: [],
          tenantParentExpiresAt: null,
        }));
    }),
    count: mock(async () => currentAccounts.length),
    create: mock(async ({ data }: any) => ({
      ...testAccount,
      ...data,
      id: 'acct-new',
      state: 'MANAGED',
      custodyEpoch: 1,
    })),
    update: mock(async ({ data }: any) => ({ ...testAccount, ...data })),
  },
  managedAccountOperation: {
    findFirst: mock(async () => null),
    create: mock(async ({ data }: any) => ({ id: 'op-1', ...data })),
    upsert: mock(async ({ create }: any) => ({ id: 'op-1', ...create })),
    delete: mock(async () => ({})),
  },
  ethereumKey: {
    create: mock(async ({ data }: any) => ({
      id: 'key-new', address: '0x2222222222222222222222222222222222222222',
      userId: null, sealedBlob: 'sealed', sealingContext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ',
      ...data,
    })),
  },
  keyCustody: {
    create: mock(async ({ data }: any) => ({ id: 'custody-1', ...data })),
  },
  possessionEvent: {
    create: mock(async ({ data }: any) => ({ id: 'event-1', ...data })),
  },
  managedAccountPolicy: {
    upsert: mock(async () => ({})),
  },
  planEntitlements: {
    findUnique: mock(async () => planEntitlements),
  },
  organization: {
    findUnique: mock(async () => ({ id: 'org-1', plan: 'FREE', planEntitlements })),
  },
  organizationServerCredential: {
    findFirst: mock(async ({ where }: any) => {
      if (where.id !== credential.id || where.organizationId !== credential.organizationId) return null;
      if (credential.revokedAt !== null) return null;
      return credential;
    }),
  },
  oauthClient: {
    findUnique: mock(async () => ({ type: 'spa' })),
    update: mock(async ({ data }: any) => ({
      id: 'oauth-client-row',
      clientId: 'ok_testclient',
      name: 'Test client',
      uri: null,
      icon: null,
      redirectUris: ['https://app.example/callback'],
      type: 'spa',
      disabled: false,
      createdAt: now,
      ...data,
    })),
  },
};

// Use real viem implementations for wallet operations so possession-event
// signature verification in signPossessionEvent uses the correct address.
// seal/unseal/generatePrivateKey return deterministic test values.
const TEST_PRIVATE_KEY_ROUTES = ('0x' + '11'.repeat(32)) as `0x${string}`;
const TEST_ADDRESS_ROUTES = privateKeyToAccount(TEST_PRIVATE_KEY_ROUTES).address;

// Apply boundary fakes inside beforeAll so that mock.restore() runs in a
// deterministic position AFTER the previous test file's afterAll has
// completed.  Top-level mock.module calls execute at file-parse time and
// cannot reliably clear stubs that another file's beforeAll installed via
// a matching mock.module call in the shared Bun module registry.
beforeAll(async () => {
  // Drop every module mock factory from earlier test files.
  // IMPORTANT: mock.restore() removes factory entries but does NOT evict
  // already-cached mocked modules from Bun's shared module registry.
  // Modules that were mocked by tenant-accounts.test.ts (service, route) are
  // still in the cache as stubs.  We fix this below using the ?__fresh trick.
  mock.restore();

  mock.module('@openkey/db', () => ({
    createPrismaClient: () => prisma,
    Prisma: {
      JsonNull: null,
      TransactionIsolationLevel: { Serializable: 'Serializable', ReadCommitted: 'ReadCommitted' },
    },
  }));

  mock.module('@openkey/tee', () => ({
    createTeeClient: () => ({ deriveKey: async () => new Uint8Array(32) }),
    generatePrivateKey: () => TEST_PRIVATE_KEY_ROUTES,
    getAddressFromPrivateKey: (pk: `0x${string}`) => privateKeyToAccount(pk).address,
    seal: async () => 'sealed',
    unseal: async () => TEST_PRIVATE_KEY_ROUTES,
    createWalletFromPrivateKey: (pk: `0x${string}`) => privateKeyToAccount(pk),
    isProductionTee: false,
  }));

  mock.module('../middleware/organization', () => ({
    requireOrganizationCredential: createMiddleware(async (c, next) => {
      const authHeader = c.req.header('Authorization');
      if (!authHeader) return c.json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } }, 401);
      c.set('organizationActor', {
        credentialId: 'cred-1',
        organizationId: 'org-1',
        subjectUserId: 'user-1',
        kind: 'MANAGEMENT',
      });
      await next();
    }),
  }));

  mock.module('../middleware/session', () => ({
    requireSession: createMiddleware(async (c, next) => {
      const userId = c.req.header('x-test-user');
      if (!userId) return c.json({ error: 'Unauthorized' }, 401);
      c.set('user', { id: userId, email: `${userId}@example.com` });
      c.set('session', { id: `session-${userId}`, userId, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }));

  // Bun's mock.restore() clears factory entries but leaves already-cached
  // mocked modules in the registry.  A preceding test file may have left
  // ../services/tenant-managed-accounts and ../routes/tenant-accounts cached
  // as stubs.  Fix: import each via a unique query-param path (different
  // registry key → fresh disk evaluation), then replace the canonical path
  // entry via mock.module so subsequent plain imports get the real module.
  // Using a variable for the path avoids TypeScript literal-path resolution.
  const svcPath = '../services/tenant-managed-accounts?__fresh=routes';
  const freshSvc = await import(svcPath);
  mock.module('../services/tenant-managed-accounts', () => ({ ...freshSvc }));

  const routePath = '../routes/tenant-accounts?__fresh=routes';
  const freshRoute = await import(routePath);
  mock.module('../routes/tenant-accounts', () => ({ ...freshRoute }));
});

// Restore all module mocks after this file's tests complete so that subsequent
// test files in the same Bun worker see a clean module registry.
afterAll(() => { mock.restore(); });

// Reset per-test state; clear mocks that accumulate call counts.
beforeEach(() => {
  currentAccounts = [testAccount as any];
  for (const mock_ of Object.values(prisma.managedAccount) as any[]) mock_.mockClear?.();
  (prisma.managedAccountOperation.findFirst as any).mockClear?.();
  (prisma.managedAccountOperation.create as any).mockClear?.();
  (prisma.managedAccountOperation.upsert as any).mockClear?.();
  (prisma.$queryRaw as any).mockClear?.();
  (prisma.organization.findUnique as any).mockClear?.();
  // Restore the managed-account count mock to be based on currentAccounts
  (prisma.managedAccount.count as any).mockImplementation(async () => currentAccounts.length);
  // Reset to valid address so ethereumKey.create mock returns a consistent address
  (prisma.ethereumKey.create as any).mockImplementation(async ({ data }: any) => ({
    id: 'key-new', address: TEST_ADDRESS_ROUTES,
    userId: null, sealedBlob: 'sealed', sealingContext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ',
    ...data,
  }));
});

async function getTenantAccountsRouter() {
  const { tenantAccountsRouter } = await import('../routes/tenant-accounts');
  return tenantAccountsRouter;
}

async function getPersonalManagedAccountsRouter() {
  const { personalManagedAccountsRouter } = await import('../routes/personal-managed-accounts');
  return personalManagedAccountsRouter;
}

describe('GET /v1/accounts - list accounts', () => {
  test('returns accounts with id field (not managedAccountId)', async () => {
    const router = await getTenantAccountsRouter();
    const res = await router.request('/', {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.accounts).toBeArray();
    expect(body.accounts[0]).toHaveProperty('id', 'acct-1');
    expect(body.accounts[0]).not.toHaveProperty('managedAccountId');
    expect(body.accounts[0]).not.toHaveProperty('ownerUserId');
    expect(body.accounts[0]).not.toHaveProperty('keyId');
    expect(body.accounts[0]).toHaveProperty('subjectEmail', 'alice@example.test');
    expect(body.accounts[0]).toHaveProperty('address');
  });

  test('rejects unauthenticated requests', async () => {
    const router = await getTenantAccountsRouter();
    const res = await router.request('/');
    expect(res.status).toBe(401);
  });
});

describe('GET /v1/accounts/:id - get single account', () => {
  test('returns account with id field and tenant-safe fields only', async () => {
    const router = await getTenantAccountsRouter();
    const res = await router.request('/acct-1', {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body).toHaveProperty('id', 'acct-1');
    expect(body).toHaveProperty('subjectEmail', 'alice@example.test');
    expect(body).not.toHaveProperty('managedAccountId');
    expect(body).not.toHaveProperty('ownerUserId');
    expect(body).not.toHaveProperty('ownerDid');
  });

  test('returns 404 for unknown account', async () => {
    const router = await getTenantAccountsRouter();
    const res = await router.request('/nonexistent', {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(404);
  });
});

describe('POST /v1/accounts - create account', () => {
  test('requires Idempotency-Key header', async () => {
    const router = await getTenantAccountsRouter();
    const res = await router.request('/', {
      method: 'POST',
      headers: { Authorization: 'Bearer oksk_test', 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'new@example.test' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: { code: 'INVALID_REQUEST' } });
  });

  test('requires email in body', async () => {
    const router = await getTenantAccountsRouter();
    const res = await router.request('/', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer oksk_test',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'route-test-idem-1',
      },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });
});

describe('POST /v1/accounts/:id/disable and /restore - state transitions', () => {
  test('disable requires Idempotency-Key and expectedCustodyEpoch', async () => {
    const router = await getTenantAccountsRouter();
    const res = await router.request('/acct-1/disable', {
      method: 'POST',
      headers: { Authorization: 'Bearer oksk_test', 'Content-Type': 'application/json' },
      body: JSON.stringify({ expectedCustodyEpoch: 1 }),
    });
    // Missing Idempotency-Key
    expect(res.status).toBe(400);
  });

  test('restore on non-DISABLED account returns OPERATION_NOT_ALLOWED', async () => {
    const router = await getTenantAccountsRouter();
    // account is in MANAGED state, not DISABLED - restore should reject
    const res = await router.request('/acct-1/restore', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer oksk_test',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'restore-managed-test',
      },
      body: JSON.stringify({ expectedCustodyEpoch: 1 }),
    });
    // OPERATION_NOT_ALLOWED for non-DISABLED restore
    expect([403, 409]).toContain(res.status);
  });
});

describe('Personal dashboard: DISABLED accounts included', () => {
  test('lists DISABLED accounts alongside active ones', async () => {
    currentAccounts = [
      { ...testAccount, ownerUserId: 'user-1' } as any,
      { ...disabledAccount, ownerUserId: 'user-1' } as any,
    ];

    const router = await getPersonalManagedAccountsRouter();
    const app = new Hono();
    app.route('/', router);

    const res = await app.request('/', {
      headers: { 'x-test-user': 'user-1' },
    });
    expect(res.status).toBe(200);
    // Verify the query included DISABLED in the state filter
    const findManyCalls = (prisma.managedAccount.findMany as any).mock?.calls ?? [];
    const lastCall = findManyCalls[findManyCalls.length - 1]?.[0];
    expect(lastCall?.where?.state?.in).toContain('DISABLED');
  });
});

describe('Deprecation/Sunset headers on removed registration flow', () => {
  test('returns 410 with REGISTRATION_FLOW_REMOVED and deprecation headers', async () => {
    const router = await getTenantAccountsRouter();
    const res = await router.request('/managed-account-registration-intents', {
      method: 'POST',
      headers: { Authorization: 'Bearer oksk_test', 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(410);
    expect(res.headers.get('Deprecation')).toBe('true');
    expect(res.headers.get('Sunset')).toBeTruthy();
    const body = await res.json() as any;
    expect(body.error.code).toBe('REGISTRATION_FLOW_REMOVED');
  });
});

describe('GET /v1/accounts?cursor - strict canonical cursor validation', () => {
  // Helper: build a base64url cursor string from a plain object.
  function makeCursor(obj: object): string {
    return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
  }

  test('malformed base64url (invalid alphabet) returns INVALID_REQUEST 400, not 500', async () => {
    const router = await getTenantAccountsRouter();
    const res = await router.request('/?cursor=!!not-valid-base64url!!', {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });

  test('padded (non-minimal) base64url with trailing = is rejected', async () => {
    // base64url must not have padding. Add a trailing '=' to a valid cursor encoding.
    const validCursor = makeCursor({ id: 'x', createdAt: '2026-07-20T12:00:00.000Z' });
    expect(validCursor).not.toContain('='); // baseline: our generator produces no padding
    const padded = validCursor + '=';
    const router = await getTenantAccountsRouter();
    const res = await router.request(`/?cursor=${encodeURIComponent(padded)}`, {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });

  test('valid base64url but non-JSON payload returns INVALID_REQUEST 400', async () => {
    const router = await getTenantAccountsRouter();
    const badCursor = Buffer.from('not-json', 'utf8').toString('base64url');
    const res = await router.request(`/?cursor=${badCursor}`, {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });

  test('reordered JSON keys {"createdAt","id"} are rejected', async () => {
    // Only {"id","createdAt"} is canonical; {"createdAt","id"} must be rejected.
    const reordered = Buffer.from('{"createdAt":"2026-07-20T12:00:00.000Z","id":"x"}', 'utf8').toString('base64url');
    const router = await getTenantAccountsRouter();
    const res = await router.request(`/?cursor=${reordered}`, {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });

  test('extra JSON key beyond {id, createdAt} is rejected', async () => {
    const extraKey = makeCursor({ id: 'x', createdAt: '2026-07-20T12:00:00.000Z', extra: 'oops' } as any);
    const router = await getTenantAccountsRouter();
    const res = await router.request(`/?cursor=${extraKey}`, {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });

  test('JSON with whitespace (non-canonical) is rejected', async () => {
    // {"id": "x",...} has a space after the colon — not canonical JSON.stringify form.
    const withSpace = Buffer.from('{"id": "x","createdAt":"2026-07-20T12:00:00.000Z"}', 'utf8').toString('base64url');
    const router = await getTenantAccountsRouter();
    const res = await router.request(`/?cursor=${withSpace}`, {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });

  test('noncanonical timestamp (date-only format) is rejected', async () => {
    const dateOnly = makeCursor({ id: 'x', createdAt: '2026-07-20' });
    const router = await getTenantAccountsRouter();
    const res = await router.request(`/?cursor=${dateOnly}`, {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });

  test('malformed timestamp that matches shape regex but is an invalid calendar date is rejected', async () => {
    // "2026-13-40T00:00:00.000Z" matches /^\d{4}-\d{2}-\d{2}T.../ but is not a real date.
    const badDate = makeCursor({ id: 'x', createdAt: '2026-13-40T00:00:00.000Z' });
    const router = await getTenantAccountsRouter();
    const res = await router.request(`/?cursor=${badDate}`, {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });

  test('empty string id is rejected', async () => {
    const emptyId = makeCursor({ id: '', createdAt: '2026-07-20T12:00:00.000Z' });
    const router = await getTenantAccountsRouter();
    const res = await router.request(`/?cursor=${emptyId}`, {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });

  test('whitespace-only id is rejected', async () => {
    // id.trim() === '' — must be rejected since it identifies no real row.
    const wsId = makeCursor({ id: '   ', createdAt: '2026-07-20T12:00:00.000Z' });
    const router = await getTenantAccountsRouter();
    const res = await router.request(`/?cursor=${wsId}`, {
      headers: { Authorization: 'Bearer oksk_test' },
    });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error.code).toBe('INVALID_REQUEST');
  });
});

describe('disable durable revocation', () => {
  test('disable revokes tenant-managed OAuth tokens for the account owner', async () => {
    // Seed a MANAGED account with an owner
    const managedWithOwner = { ...testAccount, ownerUserId: 'user-1' };
    currentAccounts = [managedWithOwner as any];

    const oauthClientFindMany = mock(async () => [{ clientId: 'tm-client-1' }]);
    const accessTokenUpdateMany = mock(async () => ({ count: 1 }));
    const refreshTokenUpdateMany = mock(async () => ({ count: 1 }));
    (prisma as any).oauthClient = { findFirst: mock(async () => null), findMany: oauthClientFindMany };
    (prisma as any).oauthAccessToken = { updateMany: accessTokenUpdateMany };
    (prisma as any).oauthRefreshToken = { updateMany: refreshTokenUpdateMany };

    const router = await getTenantAccountsRouter();
    const res = await router.request('/acct-1/disable', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer oksk_test',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'disable-revoke-test',
      },
      body: JSON.stringify({ expectedCustodyEpoch: 1 }),
    });
    expect(res.status).toBe(200);
    // Token revocation must have been called for the owner's tokens
    expect(accessTokenUpdateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ userId: 'user-1' }),
        data: expect.objectContaining({ expiresAt: expect.any(Date) }),
      }),
    );
    expect(refreshTokenUpdateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ userId: 'user-1' }),
        data: expect.objectContaining({ revoked: expect.any(Date) }),
      }),
    );
  });
});

describe('POST /v1/accounts/:id/sign - digest and transaction signing', () => {
  test('digest signing uses sign({ hash }) and returns a valid secp256k1 signature', async () => {
    // The real service must call wallet.sign({ hash }) not signMessage({ raw }) for a digest.
    // wallet.sign passes the hash directly to secp256k1 without additional keccak256.
    // wallet.signMessage({ raw }) would keccak256 the digest first, producing a different
    // signature — verified here by checking the 65-byte (132 hex char) signature length and
    // by recovering the address from the raw hash, which must equal TEST_ADDRESS_ROUTES.
    const { recoverAddress } = await import('viem');
    const router = await getTenantAccountsRouter();
    const digest = ('0x' + 'ab'.repeat(32)) as `0x${string}`;
    const res = await router.request('/acct-1/sign', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer oksk_test',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'sign-digest-test',
      },
      body: JSON.stringify({ expectedCustodyEpoch: 1, digest, auditContext: 'test-audit' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body).toHaveProperty('signature');
    const sig = body.signature as string;
    expect(sig.startsWith('0x')).toBe(true);
    expect(sig.length).toBe(132); // 65 bytes = 130 hex + 0x prefix
    // Recover the signer from the raw hash (no EIP-191). The unsealed key is
    // TEST_PRIVATE_KEY_ROUTES, so the recovered address must be TEST_ADDRESS_ROUTES.
    const recovered = await recoverAddress({ hash: digest, signature: sig as `0x${string}` });
    expect(recovered.toLowerCase()).toBe(TEST_ADDRESS_ROUTES.toLowerCase());
  });

  test('transaction signing accepts a viem TransactionRequest object without parseTransaction', async () => {
    // parseTransaction expects a serialized RLP hex string; passing a plain object
    // causes "value_.replace is not a function" TypeError → 500 response.
    // The service must pass the object directly to wallet.signTransaction instead.
    const router = await getTenantAccountsRouter();
    // JSON.stringify cannot serialize BigInt; use plain numbers — wallet.signTransaction
    // accepts both number and BigInt for numeric transaction fields.
    const tx = { type: 'eip1559', chainId: 1, gas: 21000, maxFeePerGas: 1000000000, maxPriorityFeePerGas: 1000000000, nonce: 0, value: 0, to: '0x0000000000000000000000000000000000000001' };
    const res = await router.request('/acct-1/sign', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer oksk_test',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'sign-tx-test',
      },
      body: JSON.stringify({ expectedCustodyEpoch: 1, transaction: tx }),
    });
    // Must succeed (not 500) and return a signed transaction
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body).toHaveProperty('signedTransaction');
    expect((body.signedTransaction as string).startsWith('0x')).toBe(true);
  });
});

describe('OAuth client mode immutability guard', () => {
  test('PATCH /clients/:clientId rejects mode changes with IMMUTABLE_FIELD', async () => {
    process.env.ADMIN_API_KEY = 'test-admin-key';
    const { oauthAdminRouter } = await import('../routes/oauth-admin');
    const res = await oauthAdminRouter.request('/clients/ok_testclient', {
      method: 'PATCH',
      headers: {
        Authorization: 'Bearer test-admin-key',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ mode: 'PERSONAL', name: 'Updated' }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.code).toBe('IMMUTABLE_FIELD');
    delete process.env.ADMIN_API_KEY;
  });

  test('PATCH /clients/:clientId accepts the authoritative MCP scope', async () => {
    process.env.ADMIN_API_KEY = 'test-admin-key';
    const update = mock(async ({ data }: any) => ({
      id: 'oauth-client-row',
      clientId: 'ok_testclient',
      name: 'Test client',
      uri: null,
      icon: null,
      redirectUris: ['https://app.example/callback'],
      type: 'spa',
      disabled: false,
      createdAt: now,
      ...data,
    }));
    (prisma as any).oauthClient = {
      findUnique: mock(async () => ({ type: 'spa' })),
      update,
    };
    const { oauthAdminRouter } = await import('../routes/oauth-admin');
    const res = await oauthAdminRouter.request('/clients/ok_testclient', {
      method: 'PATCH',
      headers: {
        Authorization: 'Bearer test-admin-key',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ scopes: ['openid', 'tinycloud:mcp'] }),
    });
    expect(res.status).toBe(200);
    expect((update as any).mock.calls[0]?.[0].data.scopes).toEqual(['openid', 'tinycloud:mcp']);
    delete process.env.ADMIN_API_KEY;
  });
});
