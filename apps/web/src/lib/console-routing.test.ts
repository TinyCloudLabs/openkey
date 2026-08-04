// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { routeConsoleHost } from './console-routing';

const input = {
  accountHostname: 'openkey.so',
  consoleHostname: 'console.openkey.so',
  consoleOrigin: 'https://console.openkey.so',
};

describe('console host routing', () => {
  test('moves a legacy deep link to the console host without changing its journey', () => {
    expect(routeConsoleHost({
      ...input,
      hostname: 'openkey.so',
      pathname: '/console/org_123/apps',
      search: '?tab=active',
    })).toEqual({
      type: 'redirect',
      location: 'https://console.openkey.so/console/org_123/apps?tab=active',
    });
  });

  test('allows the tenant console route tree on its dedicated host', () => {
    expect(routeConsoleHost({
      ...input,
      hostname: 'console.openkey.so',
      pathname: '/console/org_123/credentials',
      search: '',
    })).toEqual({ type: 'continue' });
  });

  test('does not serve personal account pages on the console host', () => {
    expect(routeConsoleHost({
      ...input,
      hostname: 'console.openkey.so',
      pathname: '/dashboard',
      search: '',
    })).toEqual({ type: 'not-found' });
  });
});
