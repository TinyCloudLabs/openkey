import { afterAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';

const createTenantManagedAccount = mock(async () => ({
  id: 'account-1',
  subjectEmail: 'alice@example.test',
  email: 'alice@example.test',
  externalUserId: null,
  address: '0x1111111111111111111111111111111111111111',
  state: 'MANAGED',
  custodyEpoch: 1,
  createdAt: new Date('2026-07-20T00:00:00.000Z'),
  updatedAt: new Date('2026-07-20T00:00:00.000Z'),
  tenantAccess: 'NOT_REQUIRED',
  created: true,
}));

mock.module('@openkey/db', () => ({
  createPrismaClient: () => ({}),
  Prisma: { JsonNull: null },
}));

mock.module('../middleware/organization', () => ({
  requireOrganizationCredential: createMiddleware(async (c, next) => {
    c.set('organizationActor', {
      credentialId: 'credential-1',
      organizationId: 'organization-1',
      subjectUserId: 'user-1',
      kind: 'MANAGEMENT',
    });
    await next();
  }),
}));

mock.module('../services/tenant-managed-accounts', () => ({
  createTenantManagedAccount,
  disableTenantManagedAccount: mock(async () => ({ state: 'DISABLED' })),
  getTenantManagedAccount: mock(async () => ({})),
  listTenantManagedAccounts: mock(async () => ({ accounts: [], nextCursor: null })),
  resolveManagementCredential: mock(async () => ({
    credentialId: 'credential-1',
    organizationId: 'organization-1',
    subjectUserId: 'user-1',
    kind: 'MANAGEMENT',
  })),
  restoreTenantManagedAccount: mock(async () => ({ state: 'MANAGED' })),
  signTenantManagedAccount: mock(async () => ({ signature: '0x', address: '0x0' })),
  TenantManagedAccountError: class TenantManagedAccountError extends Error {
    constructor(
      readonly code: string,
      message: string,
    ) {
      super(message);
      this.name = 'TenantManagedAccountError';
    }
  },
}));

// Restore all module mocks after this file's tests complete so that module mocks
// do not persist in the Bun worker-shared module registry across test files.
afterAll(() => { mock.restore(); });

let tenantAccountsRouter: typeof import('../routes/tenant-accounts')['tenantAccountsRouter'];

beforeEach(async () => {
  createTenantManagedAccount.mockReset();
  createTenantManagedAccount.mockResolvedValue({
    id: 'account-1',
    subjectEmail: 'alice@example.test',
    email: 'alice@example.test',
    externalUserId: null,
    address: '0x1111111111111111111111111111111111111111',
    state: 'MANAGED',
    custodyEpoch: 1,
    createdAt: new Date('2026-07-20T00:00:00.000Z'),
    updatedAt: new Date('2026-07-20T00:00:00.000Z'),
    tenantAccess: 'NOT_REQUIRED',
    created: true,
  });
  tenantAccountsRouter = (await import('../routes/tenant-accounts')).tenantAccountsRouter;
});

describe('tenant accounts route', () => {
  test('returns 201 for a new account and 200 for an idempotent replay', async () => {
    const created = await tenantAccountsRouter.request('/', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': 'create-1',
        'authorization': 'Bearer oksk_test',
      },
      body: JSON.stringify({ email: 'Alice@Example.Test' }),
    });
    expect(created.status).toBe(201);

    createTenantManagedAccount.mockResolvedValueOnce({
      id: 'account-1',
      subjectEmail: 'alice@example.test',
      email: 'alice@example.test',
      externalUserId: null,
      address: '0x1111111111111111111111111111111111111111',
      state: 'MANAGED',
      custodyEpoch: 1,
      createdAt: new Date('2026-07-20T00:00:00.000Z'),
      updatedAt: new Date('2026-07-20T00:00:00.000Z'),
      tenantAccess: 'NOT_REQUIRED',
      created: false,
    });
    const replay = await tenantAccountsRouter.request('/', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': 'create-1',
        'authorization': 'Bearer oksk_test',
      },
      body: JSON.stringify({ email: 'Alice@Example.Test' }),
    });
    expect(replay.status).toBe(200);
  });
});
