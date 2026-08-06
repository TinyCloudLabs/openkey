import { expect, test } from 'bun:test';
import {
  beginPasskeyCeremony,
  issuePasskeyCeremony,
  pendingPasskeyCeremonyCount,
  recordPasskeyFreshnessAfterHook,
  recordVerifiedPasskeySession,
} from '../services/passkey-freshness';

test('records freshness only for the exact unexpired session issued by a marked ceremony', async () => {
  const now = new Date('2026-08-05T12:00:00.000Z');
  let write: any;
  const db = { session: { updateMany: async (input: any) => { write = input; return { count: 1 }; } } } as any;
  expect(issuePasskeyCeremony('exact-session', now.getTime())).toBe(true);
  expect(beginPasskeyCeremony('exact-session', now.getTime())).toBe(true);
  expect(await recordVerifiedPasskeySession(db, { session: { id: 'session-1', userId: 'user-1' } }, 'exact-session', now)).toBe(true);
  expect(write).toMatchObject({ where: { id: 'session-1', userId: 'user-1', expiresAt: { gt: now } }, data: { lastPasskeyAt: now } });
  expect(pendingPasskeyCeremonyCount(now.getTime())).toBe(0);
});

test('rejects expired and replayed ceremonies without writing freshness', async () => {
  let writes = 0;
  const db = { session: { updateMany: async () => { writes += 1; return { count: 1 }; } } } as any;
  expect(issuePasskeyCeremony('expired-ceremony', 1_000)).toBe(true);
  expect(beginPasskeyCeremony('expired-ceremony', 1_000)).toBe(true);
  expect(await recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, 'expired-ceremony', new Date(301_000))).toBe(false);
  expect(await recordVerifiedPasskeySession(db, { session: { id: 's', userId: 'u' } }, 'expired-ceremony')).toBe(false);
  expect(writes).toBe(0);
});

test('single-claims concurrent hook attempts and always returns a hook result object', async () => {
  let writes = 0;
  let entered!: () => void;
  const enteredWrite = new Promise<void>((resolve) => { entered = resolve; });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const db = { session: { updateMany: async () => { writes += 1; entered(); await gate; return { count: 1 }; } } } as any;
  expect(issuePasskeyCeremony('single-claim')).toBe(true);
  expect(beginPasskeyCeremony('single-claim')).toBe(true);
  const first = recordPasskeyFreshnessAfterHook(db, { session: { id: 's', userId: 'u' } }, 'single-claim');
  await enteredWrite;
  expect(await recordPasskeyFreshnessAfterHook(db, { session: { id: 's', userId: 'u' } }, 'single-claim')).toEqual({});
  release();
  expect(await first).toEqual({});
  expect(writes).toBe(1);
  expect(await recordPasskeyFreshnessAfterHook(db, null, null)).toEqual({});
});
