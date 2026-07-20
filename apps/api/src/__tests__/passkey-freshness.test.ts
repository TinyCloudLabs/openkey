import { expect, test } from 'bun:test';
import {
  assertFreshPasskeyUserVerification,
  beginPasskeyCeremony,
  completePasskeyCeremony,
  issuePasskeyCeremony,
  pendingPasskeyCeremonyCount,
  recordPasskeyFreshnessAfterHook,
  recordVerifiedPasskeySession,
} from '../services/passkey-freshness';
import { authorizeKeyOperation } from '../services/managed-key-authorization';

test('successful passkey verification records the exact issued session and enables EJECT', async () => {
  const now = new Date('2026-07-15T12:00:00.000Z');
  const sessions = new Map<string, { id: string; userId: string; expiresAt: Date; lastPasskeyAt: Date | null }>([['session-issued', {
    id: 'session-issued', userId: 'owner', expiresAt: new Date(now.getTime() + 60_000), lastPasskeyAt: null,
  }]]);
  const db = {
    session: {
      updateMany: async ({ where, data }: { where: { id: string; userId: string }; data: { lastPasskeyAt: Date } }) => {
        const session = sessions.get(where.id);
        if (!session || session.userId !== where.userId) return { count: 0 };
        session.lastPasskeyAt = data.lastPasskeyAt;
        return { count: 1 };
      },
      findUnique: async ({ where }: { where: { id: string } }) => sessions.get(where.id) ?? null,
    },
    managedAccount: {
      findFirst: async () => ({
        id: 'account', ownerUserId: 'owner', organizationId: 'org', keyId: 'key', state: 'MANAGED', custodyEpoch: 1, policyVersion: 1,
        key: { id: 'key', userId: 'owner', address: '0xFCAd0B19bB29D4674531d6f115237E16AfCE377c', keyType: 'MANAGED', keyPurpose: 'MANAGED_ACCOUNT', sealedBlob: 'sealed', sealingContext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
        custodyHead: { id: 'head', managedAccountId: 'account', custodianType: 'ORGANIZATION', custodianId: 'org', epoch: 1, revokedAt: null },
        organization: { planEntitlements: null }, policies: [],
      }),
    },
  } as any;

  const ceremony = 'server-issued-ceremony';
  expect(issuePasskeyCeremony(ceremony, now.getTime())).toBe(true);
  expect(beginPasskeyCeremony(ceremony, now.getTime())).toBe(true);
  const recorded = await recordVerifiedPasskeySession(db, new Response(JSON.stringify({ session: { id: 'session-issued', userId: 'owner' } }), { status: 200 }), ceremony, now);
  expect(recorded).toBe(true);
  expect(pendingPasskeyCeremonyCount(now.getTime())).toBe(0);
  expect(completePasskeyCeremony(ceremony, now.getTime())).toBe(false);
  expect(completePasskeyCeremony(ceremony, now.getTime())).toBe(false);
  const authorization = await authorizeKeyOperation(db, {
    type: 'user', sessionId: 'session-issued', managedAccountId: 'account', keyId: 'key', expectedEpoch: 1,
    request: { operation: 'EJECT', reason: 'OWNER_REQUEST' },
  }, { now });
  expect(authorization.operation).toBe('EJECT');
});

test('failed verification and replayed ceremony cannot set freshness', async () => {
  let writes = 0;
  const db = { session: { updateMany: async () => { writes += 1; return { count: 1 }; } } } as any;
  const failed = await recordVerifiedPasskeySession(db, new Response('{}', { status: 401 }), null);
  expect(failed).toBe(false);
  expect(writes).toBe(0);
  const ceremony = 'replayed-ceremony';
  expect(issuePasskeyCeremony(ceremony)).toBe(true);
  expect(beginPasskeyCeremony(ceremony)).toBe(true);
  expect(completePasskeyCeremony(ceremony)).toBe(false);
  const replay = await recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, ceremony);
  expect(replay).toBe(false);
  expect(writes).toBe(0);
});

test('missing and expired markers cannot set freshness, and the marker store is bounded', async () => {
  let writes = 0;
  const db = { session: { updateMany: async () => { writes += 1; return { count: 1 }; } } } as any;
  expect(await recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, null)).toBe(false);
  const expired = 'expired-ceremony';
  expect(issuePasskeyCeremony(expired, 1_000)).toBe(true);
  expect(beginPasskeyCeremony(expired, 1_000)).toBe(true);
  expect(await recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, expired, new Date(1_000 + 5 * 60 * 1000))).toBe(false);
  expect(writes).toBe(0);
  expect(pendingPasskeyCeremonyCount(1_000 + 5 * 60 * 1000)).toBe(0);
});

test('custody freshness requires UV only for the marked ceremony', () => {
  expect(() => assertFreshPasskeyUserVerification({ authenticationInfo: { userVerified: false } })).toThrow();
  expect(() => assertFreshPasskeyUserVerification({ authenticationInfo: { userVerified: true } })).not.toThrow();
});

test('Better Auth after hook always returns a result object', async () => {
  const db = {
    session: { updateMany: async () => ({ count: 0 }) },
  } as any;

  expect(await recordPasskeyFreshnessAfterHook(db, null, null)).toEqual({});
});

test('concurrent hook invocations single-claim one marker and write freshness once', async () => {
  const ceremony = 'concurrent-ceremony';
  expect(issuePasskeyCeremony(ceremony)).toBe(true);
  expect(beginPasskeyCeremony(ceremony)).toBe(true);

  let writes = 0;
  let enteredResolve!: () => void;
  const entered = new Promise<void>((resolve) => { enteredResolve = resolve; });
  let release!: () => void;
  const writeGate = new Promise<void>((resolve) => { release = resolve; });
  const db = {
    session: {
      updateMany: async () => {
        writes += 1;
        enteredResolve();
        await writeGate;
        return { count: 1 };
      },
    },
  } as any;

  const first = recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, ceremony);
  await entered;
  const replay = recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, ceremony);
  expect(await replay).toBe(false);
  release();
  expect(await first).toBe(true);
  expect(writes).toBe(1);
  expect(pendingPasskeyCeremonyCount()).toBe(0);
});
