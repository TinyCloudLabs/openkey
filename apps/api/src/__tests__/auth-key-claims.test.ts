import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';

process.env.BETTER_AUTH_URL = 'https://api.openkey.test';
process.env.BETTER_AUTH_SECRET = 'test-secret';
process.env.WEBAUTHN_RP_ID = 'openkey.test';
process.env.WEBAUTHN_ORIGIN = 'https://openkey.test';
process.env.NODE_ENV = 'test';
process.env.TEE_MODE = 'development';
process.env.RESEND_API_KEY = '';
process.env.GOOGLE_CLIENT_ID = '';
process.env.GOOGLE_CLIENT_SECRET = '';

const ensureTenantManagedAccountForVerifiedEmail = mock(async () => ({
  id: 'managed-account-1',
  created: true,
}));

const prisma = {
  managedAccount: {
    findFirst: mock(async ({ where }: any) => {
      if (where.id === 'managed-account-1' && where.organizationId === 'org-1') {
        return {
          key: {
            id: 'tenant-key-1',
            address: '0x1111111111111111111111111111111111111111',
            keyType: 'MANAGED',
          },
        };
      }
      if (where.organizationId === 'org-1' && where.subjectEmail === 'alice@example.test') {
        return {
          key: {
            id: 'tenant-key-1',
            address: '0x1111111111111111111111111111111111111111',
            keyType: 'MANAGED',
          },
        };
      }
      return null;
    }),
  },
  ethereumKey: {
    findFirst: mock(async () => ({
      id: 'canonical-key-1',
      address: '0x3333333333333333333333333333333333333333',
    })),
    findMany: mock(async ({ where }: any) => {
      if (where.userId !== 'user-1') return [];
      return [
        {
          id: 'personal-key-1',
          address: '0x2222222222222222222222222222222222222222',
          keyType: 'MANAGED',
        },
      ];
    }),
  },
  oauthClient: {
    findFirst: mock(async () => ({
      metadata: { openkeyClientMode: 'TENANT_MANAGED', openkeyOrganizationId: 'org-1' },
      mode: 'TENANT_MANAGED',
    })),
  },
} as any;

mock.module('@openkey/db', () => ({
  createPrismaClient: () => prisma,
  Prisma: { JsonNull: null },
}));

// Use real crypto implementations for createWalletFromPrivateKey and getAddressFromPrivateKey
// so that mock.module leakage to managed-key-authorization.test.ts does not break the
// canonical hash test there. seal/unseal are intercepted but return a valid private key.
const TEST_PRIVATE_KEY_AUTH = ('0x' + '11'.repeat(32)) as `0x${string}`;
mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({ deriveKey: async () => new Uint8Array(32) }),
  createWalletFromPrivateKey: (pk: `0x${string}`) => privateKeyToAccount(pk),
  seal: async () => 'sealed',
  unseal: async () => TEST_PRIVATE_KEY_AUTH,
  generatePrivateKey: () => TEST_PRIVATE_KEY_AUTH,
  getAddressFromPrivateKey: (pk: `0x${string}`) => privateKeyToAccount(pk).address,
  isProductionTee: false,
}));

let buildKeyClaims: typeof import('../auth')['buildKeyClaims'];
let buildOauthKeyClaims: typeof import('../auth')['buildOauthKeyClaims'];
let buildUserInfoKeyClaims: typeof import('../auth')['buildUserInfoKeyClaims'];
let buildCanonicalTinyCloudIdentityClaim: typeof import('../auth')['buildCanonicalTinyCloudIdentityClaim'];

beforeAll(async () => {
  // Pre-load the real service module into Bun's module cache BEFORE mocking it.
  // This establishes a "baseline" that mock.restore() can revert to after this
  // file's tests complete, preventing the mock from persisting in the module cache
  // and leaking into tenant-accounts-routes.test.ts (which needs the real service).
  const realService = await import('../services/tenant-managed-accounts');

  // Register the service stub INSIDE beforeAll so it is scoped to this test file's
  // execution and does not leak into co-located test files via Bun's worker-shared
  // module registry. The stub exports ALL names imported by auth.ts so that the
  // module is fully resolved when auth is imported below.
  // normalizeSubjectEmail is imported from the real service to avoid copying the
  // ASCII-only trim logic (Unicode trim would mask normalization regressions).
  mock.module('../services/tenant-managed-accounts', () => ({
    ensureTenantManagedAccountForVerifiedEmail,
    normalizeSubjectEmail: realService.normalizeSubjectEmail,
    TenantManagedAccountError: class TenantManagedAccountError extends Error {
      code: string;
      constructor(code: string, message: string) { super(message); this.code = code; this.name = 'TenantManagedAccountError'; }
    },
    createTenantManagedAccount: mock(async () => ({})),
    listTenantManagedAccounts: mock(async () => ({ accounts: [], nextCursor: null })),
    getTenantManagedAccount: mock(async () => ({})),
    tenantSafeAccount: mock(async () => ({})),
    bindAccountsForVerifiedEmail: mock(async () => 0),
    signTenantManagedAccount: mock(async () => ({})),
    disableTenantManagedAccount: mock(async () => ({})),
    restoreTenantManagedAccount: mock(async () => ({})),
    resolveManagementCredential: mock(async () => ({ credentialId: 'cred-1', organizationId: 'org-1', subjectUserId: null, kind: 'MANAGEMENT' as const })),
  }));
  ({
    buildKeyClaims,
    buildOauthKeyClaims,
    buildUserInfoKeyClaims,
    buildCanonicalTinyCloudIdentityClaim,
  } = await import('../auth'));
});

// Restore all module mocks after this file's tests complete so that subsequent
// test files run in the same Bun worker see the real module registry.
afterAll(() => { mock.restore(); });

beforeEach(() => {
  ensureTenantManagedAccountForVerifiedEmail.mockClear();
  ensureTenantManagedAccountForVerifiedEmail.mockImplementation(async () => ({
    id: 'managed-account-1',
    created: true,
  }));
  prisma.managedAccount.findFirst.mockClear();
  prisma.managedAccount.findFirst.mockImplementation(async ({ where }: any) => {
    if (where.id === 'managed-account-1' && where.organizationId === 'org-1') {
      return {
        key: {
          id: 'tenant-key-1',
          address: '0x1111111111111111111111111111111111111111',
          keyType: 'MANAGED',
        },
      };
    }
    if (where.organizationId === 'org-1' && where.subjectEmail === 'alice@example.test') {
      return {
        state: 'MANAGED',
        key: {
          id: 'tenant-key-1',
          address: '0x1111111111111111111111111111111111111111',
          keyType: 'MANAGED',
        },
      };
    }
    return null;
  });
  prisma.ethereumKey.findMany.mockClear();
  prisma.ethereumKey.findFirst.mockClear();
});

describe('oauth key claims', () => {
  test('manage-key consent exposes one canonical identity only to a personal client', async () => {
    const personal = await buildCanonicalTinyCloudIdentityClaim(
      { id: 'user-1' },
      ['openid', 'tinycloud:manage-key'],
      { mode: 'PERSONAL', organizationId: null },
    );
    expect(personal).toEqual({
      version: 'v1',
      keyId: 'canonical-key-1',
      address: '0x3333333333333333333333333333333333333333',
      chainId: 1,
      did: 'did:pkh:eip155:1:0x3333333333333333333333333333333333333333',
      spaceId: 'tinycloud:pkh:eip155:1:0x3333333333333333333333333333333333333333:applications',
    });
    expect(prisma.ethereumKey.findFirst).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ userId: 'user-1', isCanonicalTinyCloud: true }),
    }));

    const tenant = await buildCanonicalTinyCloudIdentityClaim(
      { id: 'user-1' },
      ['tinycloud:manage-key'],
      { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
    );
    expect(tenant).toBeUndefined();
  });

  test('canonical identity claims normalize a stored address to EIP-55', async () => {
    prisma.ethereumKey.findFirst.mockImplementationOnce(async () => ({
      id: 'canonical-key-2',
      address: '0x31d40b62c395b9418c4198363619b11c65cd406f',
    }));

    await expect(buildCanonicalTinyCloudIdentityClaim(
      { id: 'user-1' },
      ['tinycloud:manage-key'],
      { mode: 'PERSONAL', organizationId: null },
    )).resolves.toMatchObject({
      address: '0x31d40B62C395B9418C4198363619B11c65cD406F',
      did: 'did:pkh:eip155:1:0x31d40B62C395B9418C4198363619B11c65cD406F',
      spaceId: 'tinycloud:pkh:eip155:1:0x31d40B62C395B9418C4198363619B11c65cD406F:applications',
    });
  });

  test('tenant-managed consent returns only the managed key and provisions the account when missing', async () => {
    const claims = await buildKeyClaims(
      { id: 'user-1', email: 'Alice@Example.Test', emailVerified: true },
      ['openid', 'keys'],
      { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
      true,
    );

    expect(ensureTenantManagedAccountForVerifiedEmail).toHaveBeenCalledWith(
      expect.anything(),
      { organizationId: 'org-1', email: 'Alice@Example.Test', userId: 'user-1' },
    );
    expect(prisma.ethereumKey.findMany).not.toHaveBeenCalled();
    expect(claims).toEqual([
      {
        address: '0x1111111111111111111111111111111111111111',
        keyId: 'tenant-key-1',
        keyType: 'MANAGED',
      },
    ]);
  });

  test('personal consent keeps personal keys separate from tenant-managed keys', async () => {
    const claims = await buildKeyClaims(
      { id: 'user-1', email: 'Alice@Example.Test', emailVerified: true },
      ['keys'],
      { mode: 'PERSONAL', organizationId: null },
      true,
    );

    expect(ensureTenantManagedAccountForVerifiedEmail).not.toHaveBeenCalled();
    expect(prisma.ethereumKey.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ userId: 'user-1', keyPurpose: 'PERSONAL', archivedAt: null }),
      }),
    );
    expect(claims).toEqual([
      {
        address: '0x2222222222222222222222222222222222222222',
        keyId: 'personal-key-1',
        keyType: 'MANAGED',
      },
    ]);
  });

  test('tinycloud session claims query only managed unarchived personal keys', async () => {
    const claims = await buildKeyClaims(
      { id: 'user-1', email: 'Alice@Example.Test', emailVerified: true },
      ['keys', 'tinycloud:session'],
      { mode: 'PERSONAL', organizationId: null },
      true,
    );

    expect(prisma.ethereumKey.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          userId: 'user-1',
          keyPurpose: 'PERSONAL',
          keyType: 'MANAGED',
          archivedAt: null,
        },
      }),
    );
    expect(claims).toHaveLength(1);
  });

  test('tinycloud session claims never expose tenant-managed keys', async () => {
    const claims = await buildKeyClaims(
      { id: 'user-1', email: 'Alice@Example.Test', emailVerified: true },
      ['keys', 'tinycloud:session'],
      { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
      true,
    );
    expect(claims).toEqual([]);
    expect(ensureTenantManagedAccountForVerifiedEmail).not.toHaveBeenCalled();
    expect(prisma.managedAccount.findFirst).not.toHaveBeenCalled();
  });

  test.each([
    ['TENANT_ACCESS_ENDED', 'This account is now user-owned'],
    ['ACCOUNT_DISABLED', 'This tenant-managed account is disabled'],
  ] as const)('maps %s to a defined OAuth client error at auth-code boundary', async (code, message) => {
    ensureTenantManagedAccountForVerifiedEmail.mockImplementationOnce(async () => {
      throw Object.assign(new Error(code), { code });
    });

    try {
      await buildOauthKeyClaims(
        { id: 'user-1', email: 'Alice@Example.Test', emailVerified: true },
        ['openid', 'keys'],
        { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
      );
      throw new Error('expected OAuth key claims to reject');
    } catch (error) {
      expect(error).toMatchObject({
        status: 'FORBIDDEN',
        body: expect.objectContaining({ code }),
      });
      expect((error as Error).message).toContain(message);
    }
  });

  test.each([
    ['DISABLED', 'ACCOUNT_DISABLED', 'This tenant-managed account is disabled'],
    ['USER_OWNED', 'TENANT_ACCESS_ENDED', 'This account is now user-owned'],
  ] as const)('buildUserInfoKeyClaims returns FORBIDDEN for %s account at userinfo boundary', async (state, code, message) => {
    prisma.managedAccount.findFirst.mockImplementationOnce(async () => ({
      state,
      key: { id: 'tenant-key-1', address: '0x1111111111111111111111111111111111111111', keyType: 'MANAGED' },
    }));

    try {
      await buildUserInfoKeyClaims(
        { id: 'user-1', email: 'Alice@Example.Test', emailVerified: true },
        ['openid', 'keys'],
        { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
      );
      throw new Error('expected buildUserInfoKeyClaims to reject');
    } catch (error) {
      expect(error).toMatchObject({
        status: 'FORBIDDEN',
        body: expect.objectContaining({ code }),
      });
      expect((error as Error).message).toContain(message);
    }
  });

  test('buildUserInfoKeyClaims returns key claims for active MANAGED account', async () => {
    prisma.managedAccount.findFirst.mockImplementationOnce(async () => ({
      state: 'MANAGED',
      key: { id: 'tenant-key-1', address: '0x1111111111111111111111111111111111111111', keyType: 'MANAGED' },
    }));

    const claims = await buildUserInfoKeyClaims(
      { id: 'user-1', email: 'Alice@Example.Test', emailVerified: true },
      ['openid', 'keys'],
      { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
    );
    expect(claims).toEqual([{
      address: '0x1111111111111111111111111111111111111111',
      keyId: 'tenant-key-1',
      keyType: 'MANAGED',
    }]);
    // Must not provision at userinfo time
    expect(ensureTenantManagedAccountForVerifiedEmail).not.toHaveBeenCalled();
  });

  test('already-issued tokens cannot retrieve claims for a disabled account', async () => {
    // Simulates a refresh-token use after disable: the account is DISABLED, and
    // the userinfo endpoint (or token refresh re-issuing id_token) must reject.
    prisma.managedAccount.findFirst.mockImplementationOnce(async () => ({
      state: 'DISABLED',
      key: { id: 'tenant-key-1', address: '0x1111111111111111111111111111111111111111', keyType: 'MANAGED' },
    }));
    try {
      await buildUserInfoKeyClaims(
        { id: 'user-1', email: 'Alice@Example.Test', emailVerified: true },
        ['keys'],
        { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
      );
      throw new Error('expected rejection');
    } catch (error) {
      expect((error as any)?.body?.code).toBe('ACCOUNT_DISABLED');
    }
  });

  test('already-issued tokens cannot retrieve claims for an ejected account', async () => {
    prisma.managedAccount.findFirst.mockImplementationOnce(async () => ({
      state: 'USER_OWNED',
      key: { id: 'tenant-key-1', address: '0x1111111111111111111111111111111111111111', keyType: 'MANAGED' },
    }));
    try {
      await buildUserInfoKeyClaims(
        { id: 'user-1', email: 'Alice@Example.Test', emailVerified: true },
        ['keys'],
        { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
      );
      throw new Error('expected rejection');
    } catch (error) {
      expect((error as any)?.body?.code).toBe('TENANT_ACCESS_ENDED');
    }
  });

  test('buildOauthKeyClaims maps ACCOUNT_IDENTITY_CONFLICT to FORBIDDEN at auth-code boundary', async () => {
    ensureTenantManagedAccountForVerifiedEmail.mockImplementationOnce(async () => {
      throw Object.assign(new Error('ACCOUNT_IDENTITY_CONFLICT'), { code: 'ACCOUNT_IDENTITY_CONFLICT' });
    });
    try {
      await buildOauthKeyClaims(
        { id: 'user-2', email: 'alice@example.test', emailVerified: true },
        ['openid', 'keys'],
        { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
      );
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toMatchObject({
        status: 'FORBIDDEN',
        body: expect.objectContaining({ code: 'ACCOUNT_IDENTITY_CONFLICT' }),
      });
    }
  });

  test('buildUserInfoKeyClaims returns empty claims when account is bound to a different user', async () => {
    // Simulates the ownerUserId filter: findFirst returns null because the account is owned by another user
    prisma.managedAccount.findFirst.mockImplementationOnce(async () => null);
    const claims = await buildUserInfoKeyClaims(
      { id: 'user-2', email: 'alice@example.test', emailVerified: true },
      ['keys'],
      { mode: 'TENANT_MANAGED', organizationId: 'org-1' },
    );
    expect(claims).toEqual([]);
    expect(ensureTenantManagedAccountForVerifiedEmail).not.toHaveBeenCalled();
  });
});
