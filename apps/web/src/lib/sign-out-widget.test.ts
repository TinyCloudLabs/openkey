// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { readSignOutWidgetRequest } from './sign-out-widget';

const source = {} as MessageEventSource;
const request = {
  type: 'openkey:sign-out:request',
  requestId: 'sign-out-1',
  protocolVersion: 1,
  sessionToken: 'bearer',
};

describe('sign-out widget transport', () => {
  test('accepts only a versioned request from the exact configured SDK origin and source', () => {
    expect(readSignOutWidgetRequest(
      { origin: 'https://app.example', source, data: request },
      'https://app.example',
      source,
    )).toEqual({ requestId: 'sign-out-1', protocolVersion: 1, sessionToken: 'bearer' });
  });

  test('refuses wildcard, foreign-origin, foreign-source, and malformed requests', () => {
    expect(readSignOutWidgetRequest(
      { origin: 'https://app.example', source, data: request }, null, source,
    )).toBeNull();
    expect(readSignOutWidgetRequest(
      { origin: 'https://evil.example', source, data: request }, 'https://app.example', source,
    )).toBeNull();
    expect(readSignOutWidgetRequest(
      { origin: 'https://app.example', source: {} as MessageEventSource, data: request },
      'https://app.example', source,
    )).toBeNull();
    expect(readSignOutWidgetRequest(
      { origin: 'https://app.example', source, data: { ...request, requestId: '' } },
      'https://app.example', source,
    )).toBeNull();
  });
});
