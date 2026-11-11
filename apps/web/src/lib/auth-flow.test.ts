// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { normalizeAuthReturnTo, normalizeRegisterReturnTo, safeOAuthAuthorizeQuery } from './auth-flow';

const refusedApprovalReturns = [
  'https://evil.example/a/abc',
  '//evil.example/a/abc',
  '/a/../dashboard',
  '/a/abc/../../dashboard',
  '/a/',
  '/a',
  '/a/abc/extra',
  '/a/abc?x=1',
  '/a/abc#frag',
  '/a/%2e%2e/dashboard',
  '/a/abc%2Fdef',
  '/a/ab%00c',
  String.raw`/a\abc`,
  String.raw`\\evil.example\a\abc`,
  ' /a/abc',
  '/a/abc ',
  '/a/ab\nc',
];

describe('approval request auth return URLs', () => {
  test('register accepts only a canonical approval path and preserves legacy targets', () => {
    expect(normalizeRegisterReturnTo('/a/abc_DEF-123', 'https://openkey.so')).toBe('/a/abc_DEF-123');
    expect(normalizeRegisterReturnTo('/a/'.concat('x'.repeat(10000)), 'https://openkey.so')).toBe(`/a/${'x'.repeat(10000)}`);
    for (const value of refusedApprovalReturns) {
      expect(normalizeRegisterReturnTo(value, 'https://openkey.so')).toBeNull();
    }
    expect(normalizeRegisterReturnTo('/delegate?x=1', 'https://openkey.so')).toBe('/delegate?x=1');
    expect(normalizeRegisterReturnTo('/widget/embed/connect', 'https://openkey.so')).toBe('/widget/embed/connect');
  });

  test('email sign-in accepts only a canonical approval path and preserves legacy targets', () => {
    expect(normalizeAuthReturnTo('/a/abc_DEF-123', 'https://openkey.so')).toBe('/a/abc_DEF-123');
    for (const value of refusedApprovalReturns) {
      expect(normalizeAuthReturnTo(value, 'https://openkey.so')).toBeNull();
    }
    for (const value of ['/console/org_123', '/dashboard', '/delegate?x=1', '/oauth/authorize', '/widget/connect']) {
      expect(normalizeAuthReturnTo(value, 'https://openkey.so')).toBe(value);
    }
  });
});

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
  const source = new URLSearchParams({ client_id: 'native', tinycloud_request: 'request-1', prompt: 'consent', login_hint: 'user@example.test', login_method: 'email',
    exp: '123', ba_iat: '100', ba_pl: 'session', sig: 'signature', ignored: 'value' });
  const query = new URLSearchParams(safeOAuthAuthorizeQuery(source));
  expect(query.get('tinycloud_request')).toBe('request-1');
  expect(query.get('prompt')).toBe('consent');
  expect(query.get('sig')).toBe('signature');
  expect(query.get('login_method')).toBe('email');
  expect(query.get('login_hint')).toBe('user@example.test');
  expect(query.get('exp')).toBe('123');
  expect(query.get('ba_iat')).toBe('100');
  expect(query.get('ba_pl')).toBe('session');
  expect(query.has('ignored')).toBe(false);
});
