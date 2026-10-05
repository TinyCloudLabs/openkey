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
    )).toEqual({ requestId: 'sign-out-1', protocolVersion: 1 });
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

  test('ignores a parent-supplied session token (TC-688)', () => {
    const accepted = readSignOutWidgetRequest(
      { origin: 'https://app.example', source, data: { ...request, sessionToken: 42 } },
      'https://app.example',
      source,
    );
    expect(accepted).toEqual({ requestId: 'sign-out-1', protocolVersion: 1 });
    expect(accepted).not.toHaveProperty('sessionToken');
  });
});
