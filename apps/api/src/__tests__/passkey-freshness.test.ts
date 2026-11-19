import { expect, test } from 'bun:test';
import {
  beginPasskeyCeremony,
  freshStepUpPasskey,
  issuePasskeyCeremony,
  pendingPasskeyCeremonyCount,
  recordPasskeyFreshnessAfterHook,
  recordVerifiedPasskeySession,
  requireFreshPasskey,
} from '../services/passkey-freshness';
import type { PrismaClient } from '@openkey/db';

// Stand-in Prisma clients: each implements only the calls under test.
type Db = Pick<PrismaClient, 'session' | 'passkey'>;

const passkeyOf = (userId: string) => ({
  findFirst: async ({ where }: { where: { credentialID?: string; userId?: string } }) =>
    where.credentialID === 'cred-1' && where.userId === userId ? { id: 'passkey-1' } : null,
});

test('records freshness and the asserted passkey only for the exact unexpired session issued by a marked ceremony', async () => {
  const now = new Date('2026-08-05T12:00:00.000Z');
  let write: unknown;
  const db = {
    session: { updateMany: async (input: unknown) => { write = input; return { count: 1 }; } },
    passkey: passkeyOf('user-1'),
  } as unknown as Db;
  expect(issuePasskeyCeremony('exact-session', now.getTime())).toBe(true);
  expect(beginPasskeyCeremony('exact-session', now.getTime())).toBe(true);
  expect(await recordVerifiedPasskeySession(db, { session: { id: 'session-1', userId: 'user-1' } }, 'exact-session', 'cred-1', now)).toBe(true);
  expect(write).toMatchObject({
    where: { id: 'session-1', userId: 'user-1', expiresAt: { gt: now } },
    data: { lastPasskeyAt: now, lastPasskeyId: 'passkey-1' },
  });
  expect(pendingPasskeyCeremonyCount(now.getTime())).toBe(0);
});

test('never records freshness for a credential that is not the session user\'s', async () => {
  let writes = 0;
  const db = { session: { updateMany: async () => { writes += 1; return { count: 1 }; } }, passkey: passkeyOf('someone-else') } as unknown as Db;
  expect(issuePasskeyCeremony('foreign-credential')).toBe(true);
  expect(beginPasskeyCeremony('foreign-credential')).toBe(true);
  expect(await recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, 'foreign-credential', 'cred-1')).toBe(false);
  expect(await recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, 'foreign-credential', undefined)).toBe(false);
  expect(writes).toBe(0);
});

test('rejects expired and replayed ceremonies without writing freshness', async () => {
  let writes = 0;
  const db = { session: { updateMany: async () => { writes += 1; return { count: 1 }; } }, passkey: passkeyOf('u') } as unknown as Db;
  expect(issuePasskeyCeremony('expired-ceremony', 1_000)).toBe(true);
  expect(beginPasskeyCeremony('expired-ceremony', 1_000)).toBe(true);
  expect(await recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, 'expired-ceremony', 'cred-1', new Date(301_000))).toBe(false);
  expect(await recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, 'expired-ceremony', 'cred-1')).toBe(false);
  expect(writes).toBe(0);
});

test('single-claims concurrent hook attempts and always returns a hook result object', async () => {
  let writes = 0;
  let entered!: () => void;
  const enteredWrite = new Promise<void>((resolve) => { entered = resolve; });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const db = {
    session: { updateMany: async () => { writes += 1; entered(); await gate; return { count: 1 }; } },
    passkey: passkeyOf('u'),
  } as unknown as Db;
  expect(issuePasskeyCeremony('single-claim')).toBe(true);
  expect(beginPasskeyCeremony('single-claim')).toBe(true);
  const first = recordPasskeyFreshnessAfterHook(db, { session: { id: 's', userId: 'u' } }, 'single-claim', 'cred-1');
  await enteredWrite;
  expect(await recordPasskeyFreshnessAfterHook(db, { session: { id: 's', userId: 'u' } }, 'single-claim', 'cred-1')).toEqual({});
  release();
  expect(await first).toEqual({});
  expect(writes).toBe(1);
  expect(await recordPasskeyFreshnessAfterHook(db, null, null, undefined)).toEqual({});
});

// TC-1198: freshness counts only when the asserted passkey counts for step-up.
function stepUpDb(session: { lastPasskeyAt: Date | null; lastPasskeyId: string | null }, countingIds: string[]) {
  return {
    session: { findFirst: async () => session },
    passkey: {
      findFirst: async ({ where }: { where: { id: string; userId: string; countsForStepUp: boolean } }) =>
        where.userId === 'u' && where.countsForStepUp === true && countingIds.includes(where.id) ? { id: where.id } : null,
    },
  } as unknown as Db;
}

test('passkey step-up needs a fresh assertion by a passkey that counts for step-up', async () => {
  const now = new Date('2026-11-10T12:00:00.000Z');
  const fresh = new Date(now.getTime() - 60_000);
  expect(await freshStepUpPasskey(stepUpDb({ lastPasskeyAt: fresh, lastPasskeyId: 'p1' }, ['p1']), 's', 'u', 300_000, now))
    .toEqual({ id: 'p1', verifiedAt: fresh });
  // Enrolled by whoever holds the session: fresh, but it does not count.
  expect(await freshStepUpPasskey(stepUpDb({ lastPasskeyAt: fresh, lastPasskeyId: 'p2' }, ['p1']), 's', 'u', 300_000, now)).toBeNull();
  // Freshness recorded before TC-1198 carries no credential.
  expect(await freshStepUpPasskey(stepUpDb({ lastPasskeyAt: fresh, lastPasskeyId: null }, ['p1']), 's', 'u', 300_000, now)).toBeNull();
  expect(await freshStepUpPasskey(stepUpDb({ lastPasskeyAt: new Date(now.getTime() - 301_000), lastPasskeyId: 'p1' }, ['p1']), 's', 'u', 300_000, now)).toBeNull();
  expect(await freshStepUpPasskey(stepUpDb({ lastPasskeyAt: new Date(now.getTime() + 1_000), lastPasskeyId: 'p1' }, ['p1']), 's', 'u', 300_000, now)).toBeNull();
  expect(await freshStepUpPasskey(stepUpDb({ lastPasskeyAt: fresh, lastPasskeyId: 'p1' }, ['p1']), undefined, 'u', 300_000, now)).toBeNull();
});

test('requireFreshPasskey answers the typed 403 unless the passkey counts', async () => {
  const now = new Date('2026-11-10T12:00:00.000Z');
  const c = (db: unknown) => ({
    get: (key: 'session' | 'user') => (key === 'session' ? { id: 's' } : { id: 'u' }),
    json: (body: unknown, status: 403) => Response.json(body, { status }),
    db,
  });
  const session = { lastPasskeyAt: new Date(now.getTime() - 1_000), lastPasskeyId: 'p2' };
  const refused = await requireFreshPasskey(c(null), 300_000, stepUpDb(session, ['p1']), now);
  expect(refused?.status).toBe(403);
  expect(await refused?.json()).toMatchObject({ code: 'passkey_step_up_required' });
  expect(await requireFreshPasskey(c(null), 300_000, stepUpDb(session, ['p2']), now)).toBeNull();
});
