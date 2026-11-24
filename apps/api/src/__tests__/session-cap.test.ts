import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { serializeSignedCookie } from 'better-call';
import { WEB_SESSION_ABSOLUTE_CAP_SECONDS, capSessionRefresh, sessionCookieCapPlugin } from '../services/session-cap';

const DAY = 86_400_000;
const NOW = Date.UTC(2026, 9, 26, 12, 0, 0);
/** The hook's context for a request whose session was created `createdDaysAgo` days before NOW. */
const during = (createdDaysAgo: number) => ({ context: { session: { session: { createdAt: new Date(NOW - createdDaysAgo * DAY) } } } });
const refreshTo = (days: number) => ({ expiresAt: new Date(NOW + days * DAY), updatedAt: new Date(NOW) });

describe('the absolute cap on web sessions', () => {
  test('is 30 days, in one place', () => {
    expect(WEB_SESSION_ABSOLUTE_CAP_SECONDS).toBe(30 * 24 * 60 * 60);
  });

  test('a young session keeps the refresh it asked for', async () => {
    expect(await capSessionRefresh(refreshTo(7), during(2))).toBeUndefined();
    expect(await capSessionRefresh(refreshTo(7), during(0))).toBeUndefined();
  });

  test('a 29-day-old session is extended only to 30 days after it was created', async () => {
    expect(await capSessionRefresh(refreshTo(7), during(29))).toEqual({ data: { expiresAt: new Date(NOW + 1 * DAY) } });
  });

  test('a session refreshed to exactly the cap keeps it, and one a millisecond over is cut back', async () => {
    expect(await capSessionRefresh(refreshTo(7), during(23))).toBeUndefined();
    const over = { expiresAt: new Date(NOW + 7 * DAY + 1) };
    expect(await capSessionRefresh(over, during(23))).toEqual({ data: { expiresAt: new Date(NOW + 7 * DAY) } });
  });

  test('a 31-day-old session is not extended: its expiry becomes the time 30 days after it was created, which is past', async () => {
    const result = await capSessionRefresh(refreshTo(7), during(31));
    expect(result).toEqual({ data: { expiresAt: new Date(NOW - 1 * DAY) } });
  });

  test('an update that does not change the expiry is left alone', async () => {
    expect(await capSessionRefresh({}, during(40))).toBeUndefined();
    expect(await capSessionRefresh({ updatedAt: new Date(NOW) } as never, during(40))).toBeUndefined();
    expect(await capSessionRefresh({ expiresAt: undefined }, null)).toBeUndefined();
  });

  test('times given as ISO strings or epoch milliseconds are read the same way', async () => {
    const context = { context: { session: { session: { createdAt: new Date(NOW - 29 * DAY).toISOString() } } } };
    expect(await capSessionRefresh({ expiresAt: new Date(NOW + 7 * DAY).toISOString() }, context)).toEqual({ data: { expiresAt: new Date(NOW + 1 * DAY) } });
    expect(await capSessionRefresh({ expiresAt: NOW + 7 * DAY }, { context: { session: { session: { createdAt: NOW - 29 * DAY } } } })).toEqual({ data: { expiresAt: new Date(NOW + 1 * DAY) } });
  });

  /** The result must set the expiry to the moment of the call: the session ends, the update is not refused. */
  async function endsNow(refresh: () => ReturnType<typeof capSessionRefresh>) {
    const before = Date.now();
    const result = await refresh();
    const after = Date.now();
    expect(result).toBeDefined();
    const endedAt = result!.data.expiresAt.getTime();
    expect(endedAt).toBeGreaterThanOrEqual(before);
    expect(endedAt).toBeLessThanOrEqual(after);
  }

  test.each([
    ['no context', null],
    ['no session in the context', { context: {} }],
    ['a null session', { context: { session: null } }],
    ['a session without createdAt', { context: { session: { session: {} } } }],
    ['a null createdAt', { context: { session: { session: { createdAt: null } } } }],
    ['an unreadable createdAt', { context: { session: { session: { createdAt: 'not a date' } } } }],
    ['a boolean createdAt', { context: { session: { session: { createdAt: true } } } }],
  ] as Array<[string, never]>)('when the creation time is unknown (%s) the session is ended, not extended and not refused', async (_name, context) => {
    await endsNow(() => capSessionRefresh(refreshTo(7), context));
  });

  test('an unreadable new expiry ends the session', async () => {
    await endsNow(() => capSessionRefresh({ expiresAt: 'soon' }, during(2)));
    await endsNow(() => capSessionRefresh({ expiresAt: null }, during(2)));
    await endsNow(() => capSessionRefresh({ expiresAt: new Date(Number.NaN) }, during(2)));
  });
});

describe('the session cookie of a refresh made by any auth endpoint', () => {
  /** A minimal Better Auth with the cap, and a 29-day-old session due for a refresh, used on `path`. */
  async function refreshThrough(path: string, plugins = [sessionCookieCapPlugin()]) {
    const createdAt = new Date(Date.now() - 29 * DAY);
    const db = {
      user: [{ id: 'u1', email: 'u1@example.test', name: 'U', emailVerified: true, createdAt, updatedAt: createdAt }],
      session: [{ id: 's1', userId: 'u1', token: 'token-1', createdAt, updatedAt: createdAt, expiresAt: new Date(Date.now() + 3 * DAY) }],
      account: [], verification: [],
    };
    const auth = betterAuth({
      baseURL: 'https://api.test/api/auth',
      secret: 'session-cap-unit-test-secret-0123456789abcdef',
      database: memoryAdapter(db),
      logger: { disabled: true },
      session: { expiresIn: 7 * 24 * 60 * 60, updateAge: 24 * 60 * 60 },
      databaseHooks: { session: { update: { before: capSessionRefresh } } },
      plugins,
    });
    const context = await auth.$context;
    const cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, 'token-1', context.secret)).split(';')[0]!;
    const response = await auth.handler(new Request(`https://api.test/api/auth${path}`, { headers: { cookie } }));
    expect(response.status).toBe(200);
    return { maxAge: /Max-Age=(\d+)/.exec(response.headers.get('set-cookie') ?? '')?.[1], expiresAt: db.session[0]!.expiresAt.getTime() };
  }

  test('ends with the capped session, on /get-session and on /list-accounts', async () => {
    for (const path of ['/get-session', '/list-accounts']) {
      const { maxAge, expiresAt } = await refreshThrough(path);
      // The session's remaining seconds, read a moment after the hook did.
      const remaining = Math.floor((expiresAt - Date.now()) / 1000);
      expect(Number(maxAge), path).toBeGreaterThanOrEqual(remaining);
      expect(Number(maxAge), path).toBeLessThanOrEqual(remaining + 1);
      expect(remaining, path).toBeLessThanOrEqual(24 * 60 * 60);
    }
  });

  test('without the cap, Better Auth gives it the full 7 days', async () => {
    expect((await refreshThrough('/list-accounts', [])).maxAge).toBe(String(7 * 24 * 60 * 60));
  });
});
