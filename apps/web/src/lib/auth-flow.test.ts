// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { normalizeAuthReturnTo, safeOAuthAuthorizeQuery } from './auth-flow';

describe('normalizeAuthReturnTo', () => {
  test('keeps an approved console-host return URL for the account sign-in handoff', () => {
    expect(normalizeAuthReturnTo(
      'https://console.openkey.so/console/org_123/apps?tab=active#new-app',
      'https://openkey.so',
      undefined,
      { consoleOrigin: 'https://console.openkey.so' },
    )).toBe('https://console.openkey.so/console/org_123/apps?tab=active#new-app');
  });

  test('refuses an arbitrary cross-origin return URL', () => {
    expect(normalizeAuthReturnTo(
      'https://example.test/console/org_123',
      'https://openkey.so',
      undefined,
      { consoleOrigin: 'https://console.openkey.so' },
    )).toBeNull();
  });

  test('refuses console-origin lookalike paths', () => {
    expect(normalizeAuthReturnTo(
      'https://console.openkey.so/console-preview',
      'https://openkey.so',
      undefined,
      { consoleOrigin: 'https://console.openkey.so' },
    )).toBeNull();
  });
});

test('native login re-entry keeps tinycloud_request and the signed provider envelope', () => {
  const source = new URLSearchParams({ client_id: 'native', tinycloud_request: 'request-1', prompt: 'consent',
    exp: '123', ba_iat: '100', ba_pl: 'session', sig: 'signature', ignored: 'value' });
  const query = new URLSearchParams(safeOAuthAuthorizeQuery(source));
  expect(query.get('tinycloud_request')).toBe('request-1');
  expect(query.get('prompt')).toBe('consent');
  expect(query.get('sig')).toBe('signature');
  expect(query.get('exp')).toBe('123');
  expect(query.get('ba_iat')).toBe('100');
  expect(query.get('ba_pl')).toBe('session');
  expect(query.has('ignored')).toBe(false);
});
