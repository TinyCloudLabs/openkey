import { describe, expect, test } from 'bun:test';
import { safeExternalHttpUrl, safeOAuthNavigationUrl } from '../apps/web/src/lib/safe-oauth-url';

describe('browser OAuth URL sinks', () => {
  test('matches accepted server navigation cases and fails closed', () => {
    expect(safeOAuthNavigationUrl('https://app.example/callback')).toBe('https://app.example/callback');
    expect(safeOAuthNavigationUrl('http://127.0.0.1:43123/callback')).toBe('http://127.0.0.1:43123/callback');
    expect(safeOAuthNavigationUrl('myapp://auth/callback')).toBe('myapp://auth/callback');
    expect(safeOAuthNavigationUrl('javascript:alert(1)')).toBeNull();
    expect(safeOAuthNavigationUrl('http://app.example/callback')).toBeNull();
  });

  test('allows only safe HTTP(S) application metadata', () => {
    expect(safeExternalHttpUrl('https://app.example')).toBe('https://app.example');
    expect(safeExternalHttpUrl('data:text/html,owned')).toBeNull();
  });
});
