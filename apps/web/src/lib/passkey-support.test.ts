// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { passkeysSupportedFromParams, withPasskeysFlag } from './passkey-support';

describe('passkeysSupportedFromParams', () => {
  test('defaults to supported when the parameter is absent', () => {
    expect(passkeysSupportedFromParams(new URLSearchParams('origin=https%3A%2F%2Fapp.test'))).toBe(true);
  });

  test('is unsupported only for passkeys=false', () => {
    expect(passkeysSupportedFromParams(new URLSearchParams('passkeys=false'))).toBe(false);
    expect(passkeysSupportedFromParams(new URLSearchParams('passkeys=true'))).toBe(true);
    expect(passkeysSupportedFromParams(new URLSearchParams('passkeys='))).toBe(true);
  });
});

describe('withPasskeysFlag', () => {
  test('leaves the URL unchanged when passkeys are supported', () => {
    expect(withPasskeysFlag('/auth/login?redirect=%2Fx', true)).toBe('/auth/login?redirect=%2Fx');
  });

  test('appends the flag when passkeys are unsupported', () => {
    expect(withPasskeysFlag('/auth/login?redirect=%2Fx', false)).toBe('/auth/login?redirect=%2Fx&passkeys=false');
    expect(withPasskeysFlag('/auth/login', false)).toBe('/auth/login?passkeys=false');
  });
});
