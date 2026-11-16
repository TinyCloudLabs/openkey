import { expect, test } from 'bun:test';
import { ShareWindowContexts } from './share-window-context';
import { shareSessionGeneration } from './share-session-generation';
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
test('a refresh inside a request that ends the session invalidates without reading the row', async () => {
  for (const path of ['/sign-out', '/revoke-sessions']) {
    const store = new ShareWindowContexts(() => 0);
    const hooks = shareWindowSessionHooks(store);
    const issued = store.issue(account, 'request', 'https://app.test');
    let reads = 0;
    await hooks.refreshed({ id: account.authSessionId, userId: account.userId }, path, async () => { reads += 1; return null; });
    expect(reads).toBe(0);
    expect(() => store.read(issued.token, account, 'request')).toThrow();
  }
});
test('a refresh anywhere else reads the authoritative row: a changed marker invalidates, a gone row invalidates', async () => {
  const session = { id: account.authSessionId, userId: account.userId };
  for (const path of [undefined, '/get-session', '/revoke-session', '/revoke-other-sessions']) {
    const store = new ShareWindowContexts(() => 0);
    const hooks = shareWindowSessionHooks(store);
    const issued = store.issue(account, 'request', 'https://app.test');
    let reads = 0;
    await hooks.refreshed(session, path, async () => { reads += 1; return null; });
    expect(reads).toBe(1);
    expect(() => store.read(issued.token, account, 'request')).toThrow();
  }
  const row = { ...session, token: 't', createdAt: new Date(0), expiresAt: new Date(1_000) };
  const sameGeneration = { ...account, authSessionGeneration: shareSessionGeneration(row) };
  const store = new ShareWindowContexts(() => 0);
  const hooks = shareWindowSessionHooks(store);
  const issued = store.issue(sameGeneration, 'request', 'https://app.test');
  await hooks.refreshed(session, '/get-session', async () => row);
  expect(store.read(issued.token, sameGeneration, 'request')).toBe(issued.context);
  await hooks.refreshed(session, '/get-session', async () => ({ ...row, lastEmailOtpAt: new Date(5) }));
  expect(() => store.read(issued.token, sameGeneration, 'request')).toThrow();
});
