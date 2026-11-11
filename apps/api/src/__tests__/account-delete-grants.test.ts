import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { mockModules, replaceModules } from './mock-module';

// In-memory model of the tables POST /api/account/delete touches. `user.delete`
// refuses while any key_grants row still references the user, mirroring the
// ON DELETE RESTRICT foreign key on key_grants.granteeUserId. A throwing
// transaction rolls the model back, as Postgres does.
type Grant = {
  keyId?: string;
  invitedUserId?: string | null;
  invitedEmail?: string | null;
  granteeDid?: string | null;
  invitationTokenDigest?: string | null;
  acceptedAt?: Date | null;
  id: string;
  role: 'OWNER' | 'ADMIN';
  granteeUserId: string | null;
  revokedAt: Date | null;
  revokedByUserId: string | null;
};
type State = { events: Record<string, unknown>[]; users: Set<string>; grants: Grant[]; sessionLastPasskeyAt: Date };
let state: State;

function matchesGrant(grant: Grant, where: Record<string, unknown>): boolean {
  return Object.entries(where).every(([key, value]) => {
    if (key === 'OR') return (value as Record<string, unknown>[]).some(part => matchesGrant(grant, part));
    if (key === 'revokedAt') {
      if (value === null) return grant.revokedAt === null;
      return grant.revokedAt !== null; // { not: null }
    }
    return (grant as Record<string, unknown>)[key] === value;
  });
}

const db: any = {
  $queryRaw: async () => [],
  $transaction: async (callback: (tx: any) => Promise<unknown>) => {
    const snapshot = structuredClone({ users: [...state.users], grants: state.grants, events: state.events });
    try {
      return await callback(db);
    } catch (error) {
      state.users = new Set(snapshot.users);
      state.grants = snapshot.grants;
      state.events = snapshot.events;
      throw error;
    }
  },
  session: {
    findFirst: async ({ where, select }: { where: { id: string; userId: string }; select: unknown }) => {
      void select;
      return where.id === 'session_1' && where.userId === 'user_1' ? { lastPasskeyAt: state.sessionLastPasskeyAt } : null;
    },
    deleteMany: async () => ({ count: 0 }),
  },
  orgKeyGrantChallenge: { deleteMany: async () => ({ count: 0 }) },
  keyGrantEvent: { create: async ({ data }: { data: Record<string, unknown> }) => { state.events.push(data); return data; } },
  keyGrant: {
    findMany: async ({ where }: { where: Record<string, unknown> }) => state.grants.filter(grant => matchesGrant(grant, where)).map(grant => ({ ...grant })),
    count: async ({ where }: { where: Record<string, unknown> }) =>
      state.grants.filter((grant) => matchesGrant(grant, where)).length,
    updateMany: async ({ where, data }: { where: Record<string, unknown>; data: Partial<Grant> }) => {
      const matched = state.grants.filter((grant) => matchesGrant(grant, where));
      for (const grant of matched) Object.assign(grant, data);
      return { count: matched.length };
    },
  },
  ethereumKey: { deleteMany: async () => ({ count: 0 }) },
  passkey: { deleteMany: async () => ({ count: 0 }) },
  account: { deleteMany: async () => ({ count: 0 }) },
  verification: { deleteMany: async () => ({ count: 0 }) },
  user: {
    findUnique: async () => ({ email: 'user_1@example.test', emailVerified: true }),
    delete: async ({ where }: { where: { id: string } }) => {
      if (state.grants.some((grant) => grant.granteeUserId === where.id)) {
        throw new Error('Foreign key constraint failed: key_grants_granteeUserId_fkey (RESTRICT)');
      }
      state.users.delete(where.id);
      return {};
    },
  },
};

// Restored afterwards: other files in the same `bun test` run read these.
const savedEnv = { CORS_ORIGIN: process.env.CORS_ORIGIN, TEE_MODE: process.env.TEE_MODE };

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', { id: 'user_1', email: 'user_1@example.test' });
      c.set('session', { id: 'session_1' });
      return next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => db }),
});

beforeAll(() => {
  process.env.CORS_ORIGIN = 'https://openkey.test';
  process.env.TEE_MODE = 'production';
});

afterAll(() => {
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

beforeEach(() => {
  state = {
    users: new Set(['user_1', 'user_2']),
    grants: [],
    events: [],
    sessionLastPasskeyAt: new Date(),
  };
});

async function deleteAccount() {
  const { accountRouter } = await import('../routes/account?account-delete-grants-test' as string);
  return accountRouter.request('/delete', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://openkey.test' },
    body: JSON.stringify({ confirmation: 'DELETE MY ACCOUNT' }),
  });
}

describe('POST /api/account/delete and key_grants', () => {
  test('a grant revoked earlier is detached so deletion succeeds, and its revocation record is kept', async () => {
    const revokedAt = new Date('2026-01-01T00:00:00Z');
    state.grants.push({
      id: 'grant_old', role: 'ADMIN', granteeUserId: 'user_1',
      revokedAt, revokedByUserId: 'user_2',
    });

    const response = await deleteAccount();

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ success: true });
    expect(state.users.has('user_1')).toBe(false);
    expect(state.grants[0]).toEqual({
      id: 'grant_old', role: 'ADMIN', granteeUserId: null,
      revokedAt, revokedByUserId: 'user_2',
      granteeDid: null, invitedEmail: null, invitedUserId: null, invitationTokenDigest: null,
    });
  });

  test('an active ADMIN grant is revoked by the deleted user and detached', async () => {
    state.grants.push({
      id: 'grant_admin', role: 'ADMIN', granteeUserId: 'user_1',
      revokedAt: null, revokedByUserId: null,
    });

    const response = await deleteAccount();

    expect(response.status).toBe(200);
    expect(state.users.has('user_1')).toBe(false);
    expect(state.grants[0]).toMatchObject({ granteeUserId: null, revokedByUserId: 'user_1' });
    expect(state.grants[0]!.revokedAt).toBeInstanceOf(Date);
  });

  test('an active OWNER grant returns 409 and leaves the account and grant untouched', async () => {
    state.grants.push({
      id: 'grant_owner', role: 'OWNER', granteeUserId: 'user_1',
      revokedAt: null, revokedByUserId: null,
    });

    const response = await deleteAccount();

    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: 'Account owns an organization key' });
    expect(state.users.has('user_1')).toBe(true);
    expect(state.grants[0]).toEqual({
      id: 'grant_owner', role: 'OWNER', granteeUserId: 'user_1',
      revokedAt: null, revokedByUserId: null,
    });
  });
});

for (const kind of ['accepted', 'pending-account', 'pending-email'] as const) {
  test(`account deletion clears ${kind} invitation data and records the change`, async () => {
    const owner: Grant = { id: 'other-owner', keyId: 'org-key', role: 'OWNER', granteeUserId: 'user_2', revokedAt: null, revokedByUserId: null };
    const grant: Grant = { id: 'affected', keyId: 'org-key', role: 'ADMIN',
      granteeUserId: kind === 'accepted' ? 'user_1' : null,
      granteeDid: kind === 'accepted' ? 'did:pkh:eip155:1:0x1' : null,
      acceptedAt: kind === 'accepted' ? new Date() : null,
      invitedUserId: kind === 'pending-account' ? 'user_1' : null,
      invitedEmail: kind === 'pending-email' ? 'user_1@example.test' : null,
      invitationTokenDigest: 'secret-digest', revokedAt: null, revokedByUserId: null };
    state.grants.push(grant, owner);
    const response = await deleteAccount();
    expect(response.status).toBe(200);
    expect(state.users.has('user_1')).toBe(false);
    expect(state.grants[0]).toMatchObject({ granteeUserId: null, granteeDid: null, invitedUserId: null, invitedEmail: null, invitationTokenDigest: null });
    expect(state.grants[0]!.revokedAt).toBeInstanceOf(Date);
    expect(state.events).toEqual([{ keyId: 'org-key', grantId: 'affected', actorUserId: 'user_1', kind: kind === 'accepted' ? 'leave' : 'cancel' }]);
    expect(state.grants[1]).toEqual(owner);
  });
}

test('audit failure rolls deletion and personal-field cleanup back', async () => {
  const grant: Grant = { id: 'audit-grant', keyId: 'org-key', role: 'ADMIN', granteeUserId: 'user_1', acceptedAt: new Date(), granteeDid: 'personal-did', invitedEmail: 'user_1@example.test', revokedAt: null, revokedByUserId: null };
  state.grants.push(structuredClone(grant));
  const create = db.keyGrantEvent.create;
  db.keyGrantEvent.create = async () => { throw new Error('injected audit failure'); };
  try { expect((await deleteAccount()).status).toBe(500); }
  finally { db.keyGrantEvent.create = create; }
  expect(state.users.has('user_1')).toBe(true);
  expect(state.grants[0]).toEqual(grant);
  expect(state.events).toEqual([]);
});

test('deleting an unverified account leaves an email invitation for another person untouched', async () => {
  const grant: Grant = { id: 'unverified-target', keyId: 'org-key', role: 'ADMIN', granteeUserId: null,
    invitedUserId: null, invitedEmail: 'user_1@example.test', acceptedAt: null, revokedAt: null, revokedByUserId: null };
  state.grants.push(structuredClone(grant));
  const findUnique = db.user.findUnique;
  db.user.findUnique = async () => ({ email: 'user_1@example.test', emailVerified: false });
  try { expect((await deleteAccount()).status).toBe(200); }
  finally { db.user.findUnique = findUnique; }
  expect(state.grants[0]).toEqual(grant);
  expect(state.events).toEqual([]);
});
