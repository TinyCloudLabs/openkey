// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { normalizeAuthReturnTo } from './auth-flow';

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
