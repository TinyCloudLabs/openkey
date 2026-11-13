import { expect, test } from 'bun:test';
import { ShareWindowContexts } from './share-window-context';
import { shareWindowSessionHooks } from './share-window-session';
const account = { userId: 'owner', authSessionId: 'session-A', authSessionGeneration: 'generation', keyId: 'key',
  address: '0x1111111111111111111111111111111111111111', keyType: 'MANAGED' as const };
for (const event of ['sign-out', 'account-switch', 'rotation', 'update'] as const) {
  test(`auth ${event} terminally invalidates outstanding window contexts`, () => {
    const store = new ShareWindowContexts(() => 0);
    const hooks = shareWindowSessionHooks(store);
    const issued = store.issue(account, 'request', 'https://app.test');
    const previous = { id: account.authSessionId, userId: account.userId };
    if (event === 'sign-out') hooks.deleted(previous);
    else if (event === 'update') hooks.updated(previous);
    else hooks.created({ id: 'session-B', userId: event === 'account-switch' ? 'other-owner' : account.userId },
      { context: { session: { session: previous } } });
    expect(() => store.read(issued.token, account, 'request')).toThrow();
    expect(() => store.consume(issued.token, account, 'request')).toThrow();
  });
}
test('session B cannot look up or claim a token issued to session A', () => {
  const store = new ShareWindowContexts(() => 0);
  const issued = store.issue(account, 'request', 'https://app.test');
  const other = { ...account, authSessionId: 'session-B' };
  expect(() => store.read(issued.token, other, 'request')).toThrow();
  expect(() => store.consume(issued.token, other, 'request')).toThrow();
  expect(store.read(issued.token, account, 'request')).toBe(issued.context);
});
