import { beforeEach, expect, test } from 'bun:test';
import {
  normalizeAppOrigin,
  pruneAppSignIns,
  recordAppSignIn,
  resetAppSignInStateForTests,
  writeAppSignIn,
  type AppSignInDatabase,
} from '../services/app-sign-in';
import { issueAuthorizationContext, peekAuthorizationContext } from '../services/authorization-signing';

type Row = { userId: string; origin: string; day: Date };

function fakeDatabase(rows: Row[] = []): AppSignInDatabase & { rows: Row[] } {
  return {
    rows,
    appSignInDay: {
      async upsert({ where: { userId_origin_day: key }, create }) {
        const exists = rows.some((r) => r.userId === key.userId && r.origin === key.origin && r.day.getTime() === key.day.getTime());
        if (!exists) rows.push({ ...create });
        return null;
      },
      async deleteMany({ where: { day } }) {
        for (let i = rows.length - 1; i >= 0; i--) if (rows[i]!.day < day.lt) rows.splice(i, 1);
        return null;
      },
    },
  };
}

beforeEach(resetAppSignInStateForTests);

test('repeat sign-ins by the same user at the same origin on one UTC day add one row', async () => {
  const db = fakeDatabase();
  await writeAppSignIn(db, 'u1', 'https://tinycloud.chat/some/path?q=1', new Date('2026-10-19T00:00:01Z'));
  await writeAppSignIn(db, 'u1', 'https://tinycloud.chat', new Date('2026-10-19T23:59:59Z'));
  expect(db.rows).toEqual([{ userId: 'u1', origin: 'https://tinycloud.chat', day: new Date('2026-10-19T00:00:00Z') }]);
});

test('a new day, a new origin or a new user each add a row', async () => {
  const db = fakeDatabase();
  await writeAppSignIn(db, 'u1', 'https://a.example', new Date('2026-10-19T12:00:00Z'));
  await writeAppSignIn(db, 'u1', 'https://a.example', new Date('2026-10-20T00:00:00Z'));
  await writeAppSignIn(db, 'u1', 'https://b.example:8443', new Date('2026-10-20T01:00:00Z'));
  await writeAppSignIn(db, 'u2', 'https://a.example', new Date('2026-10-20T01:00:00Z'));
  expect(db.rows).toHaveLength(4);
});

test('a missing or unusable app origin records "unknown" and still counts the user', async () => {
  const db = fakeDatabase();
  const now = new Date('2026-10-19T12:00:00Z');
  for (const origin of [undefined, null, '', 'not a url', 'javascript:alert(1)', 'https://user:pw@evil.example']) {
    await writeAppSignIn(db, 'u1', origin, now);
  }
  expect(db.rows.map((r) => r.origin)).toEqual(['unknown']);
});

test('normalises to scheme://host[:port]', () => {
  expect(normalizeAppOrigin('https://App.Example.com:443/x?y#z')).toBe('https://app.example.com');
  expect(normalizeAppOrigin('http://localhost:5173/cb')).toBe('http://localhost:5173');
  expect(normalizeAppOrigin('ftp://x.example')).toBeNull();
});

test('rows older than 35 days are deleted; the 35-day boundary day is kept', async () => {
  const day = (iso: string) => new Date(`${iso}T00:00:00Z`);
  const db = fakeDatabase([
    { userId: 'u1', origin: 'unknown', day: day('2026-09-13') }, // 36 days before 2026-10-19
    { userId: 'u1', origin: 'unknown', day: day('2026-09-14') }, // exactly 35 days
    { userId: 'u1', origin: 'unknown', day: day('2026-10-19') },
  ]);
  await pruneAppSignIns(db, new Date('2026-10-19T08:00:00Z'));
  expect(db.rows.map((r) => r.day.toISOString().slice(0, 10))).toEqual(['2026-09-14', '2026-10-19']);
});

test('recording prunes expired rows as part of the write path', async () => {
  const db = fakeDatabase([{ userId: 'old', origin: 'unknown', day: new Date('2026-01-01T00:00:00Z') }]);
  await writeAppSignIn(db, 'u1', undefined, new Date('2026-10-19T12:00:00Z'));
  expect(db.rows.map((r) => r.userId)).toEqual(['u1']);
});

test('recordAppSignIn is fire-and-forget: returns void at once, never rejects, and writes in the background', async () => {
  const db = fakeDatabase();
  const result = recordAppSignIn(db, 'u1', 'https://a.example', new Date('2026-10-19T12:00:00Z'));
  expect(result).toBeUndefined();
  await Bun.sleep(0);
  expect(db.rows).toHaveLength(1);

  const failing = fakeDatabase();
  failing.appSignInDay.upsert = async () => { throw new Error('db down'); };
  expect(recordAppSignIn(failing, 'u1', 'https://a.example')).toBeUndefined();
  await Bun.sleep(0);
});

test('swallowed failures log at most once a minute, with a count and no ids', async () => {
  const db = fakeDatabase();
  db.appSignInDay.upsert = async () => { throw new Error('db down'); };
  const lines: string[] = [];
  const write = process.stdout.write;
  process.stdout.write = ((chunk: string | Uint8Array) => { lines.push(String(chunk)); return true; }) as typeof process.stdout.write;
  try {
    for (let i = 0; i < 5; i++) recordAppSignIn(db, `secret-user-${i}`, 'https://secret.example');
    await Bun.sleep(5);
  } finally {
    process.stdout.write = write;
  }
  const failures = lines.filter((l) => l.includes('app_sign_in_record_failed'));
  expect(failures).toHaveLength(1);
  expect(JSON.parse(failures[0]!).count).toBe(1);
  expect(failures[0]).not.toContain('secret');
});

test('the app origin bound at prepare time is what the final step reads', () => {
  const base = {
    userId: 'u1', keyId: 'k', keyAddress: '0xabc', jwk: { kty: 'OKP' }, host: 'https://node.example',
    spaceId: 's', baselineAbilitiesDigest: 'b', immutableFieldsDigest: 'i', allowedActionIds: new Set<string>(),
    initialSelectionActionIds: new Set<string>(), expirationTime: new Date(Date.now() + 60_000).toISOString(),
  };
  const withOrigin = issueAuthorizationContext({ ...base, appOrigin: 'https://tinycloud.chat' });
  const without = issueAuthorizationContext(base);
  const a = peekAuthorizationContext(withOrigin.token);
  const b = peekAuthorizationContext(without.token);
  expect(a.ok && a.value.appOrigin).toBe('https://tinycloud.chat');
  expect(b.ok && b.value.appOrigin).toBeUndefined();
});
