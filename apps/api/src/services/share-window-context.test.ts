import { expect, test } from 'bun:test';
import { ShareWindowContexts } from './share-window-context';
const account = { userId: 'user', authSessionId: 'session', keyId: 'key', address: '0x1111111111111111111111111111111111111111', keyType: 'MANAGED' as const };
test('window context is one-use and binds account, key, request and observed origin', () => {
  const store = new ShareWindowContexts(() => 0);
  const issued = store.issue(account, 'request', 'https://actual.example');
  expect(issued.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(issued.context.origin).toBe('https://actual.example');
  expect(issued.context.expiresAt).toBe(60_000);
  expect(() => store.issue(account, 'request', 'https://other.example')).toThrow();
  for (const other of [{ ...account, userId: 'other' }, { ...account, authSessionId: 'other' }, { ...account, keyId: 'other' }]) {
    expect(() => store.read(issued.token, other, 'request')).toThrow();
  }
  expect(() => store.read(issued.token, account, 'other-request')).toThrow();
  expect(store.consume(issued.token, account, 'request')).toBe(issued.context);
  expect(() => store.consume(issued.token, account, 'request')).toThrow();
  expect(() => store.issue(account, 'request', 'https://actual.example')).toThrow();
});
test('expiry, cancellation, key switch and sign-out are terminal', () => {
  let now = 0;
  const store = new ShareWindowContexts(() => now);
  const first = store.issue(account, 'first', 'https://actual.example');
  store.cancel(first.token, account, 'first');
  expect(() => store.read(first.token, account, 'first')).toThrow();
  const second = store.issue(account, 'second', 'https://actual.example');
  store.issue({ ...account, keyId: 'new-key' }, 'third', 'https://actual.example');
  expect(() => store.read(second.token, account, 'second')).toThrow();
  const fourth = store.issue(account, 'fourth', 'https://actual.example');
  store.invalidateSession(account.userId, account.authSessionId);
  expect(() => store.read(fourth.token, account, 'fourth')).toThrow();
  const expiry = store.issue(account, 'expiry', 'https://actual.example');
  now = 60_000;
  expect(() => store.read(expiry.token, account, 'expiry')).toThrow();
});
