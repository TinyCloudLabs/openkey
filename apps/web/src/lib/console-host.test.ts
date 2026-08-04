// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { consoleHref, isConsolePath } from './console-host';

describe('console host paths', () => {
  test('recognizes only the console route tree', () => {
    expect(isConsolePath('/console')).toBe(true);
    expect(isConsolePath('/console/org_123/apps')).toBe(true);
    expect(isConsolePath('/console-preview')).toBe(false);
    expect(isConsolePath('/dashboard')).toBe(false);
  });

  test('does not turn a host link into a protocol-relative navigation', () => {
    expect(() => consoleHref('//example.test')).toThrow('origin-relative');
  });
});
