import { describe, expect, test } from 'bun:test';
import { createCipheriv, randomBytes } from 'node:crypto';
import {
  authorizeKeyOperation,
  ManagedKeyAuthorizationError,
  type AuthorizeKeyOperationInput,
} from '../services/managed-key-authorization';
import { activateProvisionedManagedAccount, transitionManagedAccountToUserCustody } from '../services/custody-transition';
import {
  assertSealingContext,
  createSealingContext,
  resolveSealingContext,
} from '../services/key-sealing';

const now = new Date('2026-07-15T12:00:00.000Z');
const context = createSealingContext();
const tee = { deriveKey: async (_path: string) => new Uint8Array(32) } as any;

function barrierSealedBlob(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.alloc(32), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64');
}

function baseAccount() {
  return {
    id: 'account-a',
    ownerUserId: 'user-a',
    organizationId: 'org-a',
    keyId: 'key-a',
    state: 'MANAGED',
    custodyEpoch: 1,
    policyVersion: 1,
    key: {
      id: 'key-a',
      userId: 'user-a',
      address: '0xFCAd0B19bB29D4674531d6f115237E16AfCE377c',
      keyType: 'MANAGED',
      keyPurpose: 'MANAGED_ACCOUNT',
      sealedBlob: 'sealed',
      sealingContext: context,
    },
    custodyHead: {
      id: 'custody-a-1',
      managedAccountId: 'account-a',
      custodianType: 'ORGANIZATION',
      custodianId: 'org-a',
      epoch: 1,
      revokedAt: null,
    },
    nodes: [],
    tenantParentDelegationCid: 'bafy-parent',
    organization: {
      planEntitlements: {
        maxTenantDelegationTtlSeconds: 3600,
        maxTenantPolicyVersion: 1,
        maxManagedAccounts: 10,
      },
    },
    policies: [{
      version: 1,
      grants: [{ capability: 'kv', resource: 'applications/example', action: 'read' }],
      maxTtlSeconds: 1800,
    }],
  };
}

function makeDb(account = baseAccount()) {
  const state = {
    account,
    credential: {
      id: 'credential-a',
      organizationId: 'org-a',
      subjectUserId: 'member-a',
      kind: 'BROKER',
      revokedAt: null,
    },
    membership: { id: 'membership-a', role: 'ADMIN' } as { id: string; role: 'ADMIN' | 'MEMBER' } | null,
    session: {
      id: 'session-a',
      userId: 'user-a',
      expiresAt: new Date(now.getTime() + 60_000),
      lastPasskeyAt: new Date(now.getTime() - 1_000),
    },
    events: [] as Array<{ eventHash: string; id: string }>,
    passkeys: { findMany: async () => [{
      id: 'passkey-a', credentialID: 'credential-key-a', publicKey: 'public-key-a', counter: 0,
      deviceType: 'singleDevice', backedUp: false, transports: null, aaguid: null,
      createdAt: now,
    }] },
    nextCustodyId: 2,
  };
  let tail = Promise.resolve();
  const db: any = {
    managedAccount: {
      findFirst: async ({ where }: any) => {
        const matches = where.id === state.account.id && where.keyId === state.account.keyId
          && (where.organizationId === undefined || where.organizationId === state.account.organizationId)
          && (where.ownerUserId === undefined || where.ownerUserId === state.account.ownerUserId);
        return matches ? structuredClone(state.account) : null;
      },
      update: async ({ data }: any) => {
        Object.assign(state.account, data);
        return state.account;
      },
      count: async () => 1,
    },
    organizationServerCredential: {
      findUnique: async ({ where }: any) => where.id === state.credential.id ? state.credential : null,
    },
    organizationMembership: {
      findFirst: async ({ where }: any) => state.membership
        && (where.role === undefined || where.role === state.membership.role) ? state.membership : null,
    },
    session: {
      findUnique: async ({ where }: any) => where.id === state.session.id ? state.session : null,
    },
    ethereumKey: {
      findUnique: async ({ where }: any) => where.id === state.account.key.id ? structuredClone(state.account.key) : null,
    },
    passkey: state.passkeys,
    keyCustody: {
      update: async ({ data }: any) => {
        state.account.custodyHead.revokedAt = data.revokedAt;
      },
      create: async ({ data }: any) => {
        const head = { id: `custody-a-${state.nextCustodyId++}`, ...data, revokedAt: null };
        state.account.custodyHead = head;
        return head;
      },
    },
    possessionEvent: {
      findFirst: async () => state.events.at(-1) ?? null,
      create: async ({ data }: any) => {
        const event = { id: `event-${state.events.length + 1}`, ...data };
        state.events.push(event);
        return event;
      },
    },
    oauthClient: { findMany: async () => [] },
    oauthAccessToken: { deleteMany: async () => ({ count: 0 }) },
    oauthRefreshToken: { updateMany: async () => ({ count: 0 }) },
    ejectRevocationReceipt: { createMany: async () => ({ count: 0 }) },
    ejectRequest: { update: async () => ({}) },
    webhookEndpoint: { findMany: async () => [] },
    webhookDelivery: { createMany: async () => ({ count: 0 }) },
    $transaction: async (fn: any) => {
      const run = tail.then(() => fn(db));
      tail = run.then(() => undefined, () => undefined);
      return run;
    },
    $queryRaw: async () => [],
    state,
  };
  return db;
}

function errorCode(error: unknown): string | undefined {
  return error instanceof ManagedKeyAuthorizationError ? error.code : undefined;
}

async function denied(promise: Promise<unknown>, code: string) {
  try {
    await promise;
    throw new Error(`Expected ${code}`);
  } catch (error) {
    expect(errorCode(error)).toBe(code);
  }
}

describe('sealing contexts', () => {
  test('rejects empty or malformed new contexts and accepts only 256-bit canonical values', () => {
    expect(() => assertSealingContext('')).toThrow();
    expect(() => resolveSealingContext({ userId: 'user-a', sealingContext: 'not-valid' })).toThrow();
    expect(resolveSealingContext({ userId: 'user-a', sealingContext: null })).toBe('openkey/user/user-a/keys');
    expect(context).toHaveLength(43);
  });
});

describe('managed key authorization', () => {
  const orgInput = (overrides: Partial<AuthorizeKeyOperationInput> = {}): AuthorizeKeyOperationInput => ({
    type: 'organization',
    credentialId: 'credential-a',
    managedAccountId: 'account-a',
    keyId: 'key-a',
    expectedEpoch: 1,
    request: { operation: 'REQUEST_CHILD_DELEGATION', delegation: {
      grants: [{ capability: 'kv', resource: 'applications/example', action: 'read' }], ttlSeconds: 600,
    } },
    ...overrides,
  } as AuthorizeKeyOperationInput);

  test('authorizes a policy-narrowed organization delegation', async () => {
    const db = makeDb();
    const authorized = await authorizeKeyOperation(db, orgInput(), { now });
    expect(authorized.narrowedDelegation).toEqual({
      grants: [{ capability: 'kv', resource: 'applications/example', action: 'read' }], ttlSeconds: 600,
    });
  });

  test('rejects unsafe resource/action tuples and wildcard cross-products', async () => {
    const cases = [
      { capability: 'kv', resource: '*', action: 'read' },
      { capability: 'kv', resource: 'applications/example', action: 'admin' },
      { capability: 'kv', resource: 'admin/*', action: 'write' },
      { capability: 'sql', resource: 'applications/example', action: 'read' },
      { capability: 'vault', resource: 'secrets/example', action: '*' },
    ];
    for (const grant of cases) {
      const db = makeDb();
      db.state.account.policies[0].grants = [grant];
      await denied(authorizeKeyOperation(db, orgInput({
        request: { operation: 'REQUEST_CHILD_DELEGATION', delegation: { grants: [grant], ttlSeconds: 600 } },
      }), { now }), 'DELEGATION_POLICY_DENIED');
    }
  });

  test('allows only a persisted provisioner to bootstrap PROVISIONED accounts', async () => {
    const db = makeDb();
    db.state.account.state = 'PROVISIONED';
    db.state.account.custodyHead = null;
    db.state.account.custodyEpoch = 0;
    db.state.credential.kind = 'PROVISIONER';
    const authorized = await authorizeKeyOperation(db, {
      ...orgInput(),
      expectedEpoch: 0,
      request: { operation: 'TINYCLOUD_BOOTSTRAP' },
    }, { now });
    expect(authorized.custodyEpoch).toBe(0);
  });

  test('owner EJECT succeeds while organization custody is active', async () => {
    const db = makeDb();
    const authorized = await authorizeKeyOperation(db, {
      type: 'user', sessionId: 'session-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 1,
      request: { operation: 'EJECT', reason: 'OWNER_REQUEST' },
    }, { now });
    expect(authorized.custodyEpoch).toBe(1);
  });

  test('revoked credentials and memberships fail from persisted records', async () => {
    const db = makeDb();
    db.state.credential.revokedAt = now;
    await denied(authorizeKeyOperation(db, orgInput(), { now }), 'CREDENTIAL_REVOKED');
    db.state.credential.revokedAt = null;
    db.state.membership = null;
    await denied(authorizeKeyOperation(db, orgInput(), { now }), 'MEMBERSHIP_REVOKED');
    db.state.membership = { id: 'membership-a', role: 'MEMBER' };
    await denied(authorizeKeyOperation(db, orgInput(), { now }), 'MEMBERSHIP_REVOKED');
  });

  test('freshness comes from the server session record, not an asserted boolean', async () => {
    const db = makeDb();
    db.state.session.lastPasskeyAt = new Date(now.getTime() - 6 * 60 * 1000);
    await denied(authorizeKeyOperation(db, {
      type: 'user', sessionId: 'session-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 1,
      request: { operation: 'EJECT', reason: 'OWNER_REQUEST' },
    }, { now }), 'PASSKEY_NOT_FRESH');
  });

  test('cross-tenant identifiers are indistinguishable from not found', async () => {
    const db = makeDb();
    db.state.credential.organizationId = 'org-b';
    await denied(authorizeKeyOperation(db, orgInput(), { now }), 'MANAGED_ACCOUNT_NOT_FOUND');
  });

  test('read remains available when plan entitlements are unavailable', async () => {
    const db = makeDb();
    db.state.account.organization.planEntitlements = null;
    const authorized = await authorizeKeyOperation(db, {
      ...orgInput(),
      request: { operation: 'READ_MANAGED_ACCOUNT' },
    }, { now });
    expect(authorized.managedAccountId).toBe('account-a');
  });

  test('authorization metadata has no executor, key, sealing path, or signer', async () => {
    for (const input of [
      orgInput({ request: { operation: 'READ_MANAGED_ACCOUNT' } }),
      { ...orgInput(), request: { operation: 'TINYCLOUD_BOOTSTRAP' as const } },
    ]) {
      const db = makeDb();
      if (input.request.operation === 'TINYCLOUD_BOOTSTRAP') {
        db.state.account.state = 'PROVISIONED';
        db.state.account.custodyEpoch = 0;
        db.state.account.custodyHead = null;
        db.state.credential.kind = 'PROVISIONER';
        input.expectedEpoch = 0;
      }
      const authorized = await authorizeKeyOperation(db, input, { now });
      expect(authorized).not.toHaveProperty('execute');
      expect(authorized).not.toHaveProperty('privateKey');
      expect(authorized).not.toHaveProperty('sealingContext');
      expect(authorized).not.toHaveProperty('signer');
    }
  });
});

describe('custody transition service', () => {
  test('initializes exactly once from PROVISIONED epoch 0 to organization epoch 1', async () => {
    const db = makeDb();
    db.state.account.state = 'PROVISIONED';
    db.state.account.custodyEpoch = 0;
    db.state.account.custodyHead = null;
    db.state.account.key.sealedBlob = barrierSealedBlob('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
    db.state.credential.kind = 'PROVISIONER';
    const result = await activateProvisionedManagedAccount(db, tee, {
      type: 'organization', credentialId: 'credential-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 0,
      nextEpoch: 1, request: { operation: 'TINYCLOUD_BOOTSTRAP' },
    }, now);
    expect(result).toMatchObject({ previousEpoch: 0, custodyEpoch: 1, state: 'MANAGED' });
    expect(db.state.account.custodyHead.custodianType).toBe('ORGANIZATION');
    expect(db.state.events).toHaveLength(1);
    await denied(activateProvisionedManagedAccount(db, tee, {
      type: 'organization', credentialId: 'credential-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 0,
      nextEpoch: 1, request: { operation: 'TINYCLOUD_BOOTSTRAP' },
    }, now), 'LIFECYCLE_NOT_AUTHORIZED');
  });

  test('refuses activation without an owner passkey before signing or custody mutation', async () => {
    const db = makeDb();
    db.state.account.state = 'PROVISIONED';
    db.state.account.custodyEpoch = 0;
    db.state.account.custodyHead = null;
    db.state.credential.kind = 'PROVISIONER';
    db.state.passkeys.findMany = async () => [];
    db.state.account.key.sealedBlob = barrierSealedBlob('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
    await denied(activateProvisionedManagedAccount(db, tee, {
      type: 'organization', credentialId: 'credential-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 0,
      nextEpoch: 1, request: { operation: 'TINYCLOUD_BOOTSTRAP' },
    }, now), 'OWNER_PASSKEY_REQUIRED');
    expect(db.state.account.state).toBe('PROVISIONED');
    expect(db.state.account.custodyHead).toBeNull();
    expect(db.state.events).toHaveLength(0);
  });

  test('commits exactly one next epoch and writes head, history, and event atomically', async () => {
    const db = makeDb();
    db.state.account.key.sealedBlob = barrierSealedBlob('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
    const result = await transitionManagedAccountToUserCustody(db, tee, {
      type: 'user', sessionId: 'session-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 1,
      nextEpoch: 2, request: { operation: 'EJECT', reason: 'OWNER_REQUEST' },
    }, now);
    expect(result).toMatchObject({ previousEpoch: 1, custodyEpoch: 2, state: 'USER_OWNED' });
    expect(db.state.account.custodyHead.epoch).toBe(2);
    expect(db.state.events).toHaveLength(1);
    await denied(transitionManagedAccountToUserCustody(db, tee, {
      type: 'user', sessionId: 'session-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 2,
      nextEpoch: 4, request: { operation: 'EJECT', reason: 'OWNER_REQUEST' },
    }, now), 'LIFECYCLE_NOT_AUTHORIZED');
  });

  test('rejects gaps and serializes two competing transitions', async () => {
    const db = makeDb();
    db.state.account.key.sealedBlob = barrierSealedBlob('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
    await denied(transitionManagedAccountToUserCustody(db, tee, {
      type: 'user', sessionId: 'session-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 1,
      nextEpoch: 3, request: { operation: 'EJECT', reason: 'OWNER_REQUEST' },
    }, now), 'CUSTODY_EPOCH_STALE');

    const first = transitionManagedAccountToUserCustody(db, tee, {
      type: 'user', sessionId: 'session-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 1,
      nextEpoch: 2, request: { operation: 'EJECT', reason: 'OWNER_REQUEST' },
    }, now);
    const second = transitionManagedAccountToUserCustody(db, tee, {
      type: 'user', sessionId: 'session-a', managedAccountId: 'account-a', keyId: 'key-a', expectedEpoch: 1,
      nextEpoch: 2, request: { operation: 'EJECT', reason: 'OWNER_REQUEST' },
    }, now);
    await first;
    await denied(second, 'LIFECYCLE_NOT_AUTHORIZED');
    expect(db.state.events).toHaveLength(1);
  });
});
