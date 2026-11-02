// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { Window } from 'happy-dom';

// sessionStorage is the widget's own; give this file one.
const win = new Window({ url: 'https://openkey.so/' });
Object.assign(globalThis, { window: win, sessionStorage: win.sessionStorage });

const { setSessionToken, withSessionCredential } = await import('./embed-passkey');

const base: RequestInit = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' };

describe('withSessionCredential', () => {
  beforeEach(() => sessionStorage.clear());
  afterEach(() => sessionStorage.clear());

  test('with a session token it sends the token as a bearer credential and no cookies', () => {
    setSessionToken('token-1');
    const init = withSessionCredential(base);
    expect(init.credentials).toBe('omit');
    expect(init.headers).toEqual({ 'Content-Type': 'application/json', Authorization: 'Bearer token-1' });
    expect(init.method).toBe('POST');
    expect(init.body).toBe('{}');
  });

  test('without a token it sends cookies and adds no Authorization header', () => {
    const init = withSessionCredential(base);
    expect(init.credentials).toBe('include');
    expect(init.headers).toEqual({ 'Content-Type': 'application/json' });
  });

  test('does not change the options it is given', () => {
    setSessionToken('token-2');
    const before = JSON.stringify(base);
    withSessionCredential(base);
    expect(JSON.stringify(base)).toBe(before);
  });

  test('the token in use is read at the time of the call', () => {
    setSessionToken('first');
    expect((withSessionCredential(base).headers as Record<string, string>).Authorization).toBe('Bearer first');
    setSessionToken('second');
    expect((withSessionCredential(base).headers as Record<string, string>).Authorization).toBe('Bearer second');
  });
});
