// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { readOrgSignWidgetRequest } from './org-sign-widget';

const source = {} as MessageEventSource;
const request = {
  type: 'openkey:org-sign:request',
  requestId: 'org-sign-1',
  keyId: 'key-1',
  message: 'Sign in to Example',
  protocolVersion: 1,
};

describe('org-sign widget transport', () => {
  test('accepts a versioned request from the exact requesting origin and window', () => {
    expect(readOrgSignWidgetRequest(
      { origin: 'https://app.example', source, data: request },
      'https://app.example',
      source,
    )).toEqual({
      requestId: 'org-sign-1',
      keyId: 'key-1',
      message: 'Sign in to Example',
      protocolVersion: 1,
    });
  });

  test('refuses when no verified origin is available', () => {
    expect(readOrgSignWidgetRequest(
      { origin: 'https://app.example', source, data: request }, null, source,
    )).toBeNull();
  });

  test('refuses a foreign origin and a foreign window', () => {
    expect(readOrgSignWidgetRequest(
      { origin: 'https://evil.example', source, data: request }, 'https://app.example', source,
    )).toBeNull();
    expect(readOrgSignWidgetRequest(
      { origin: 'https://app.example', source: {} as MessageEventSource, data: request },
      'https://app.example',
      source,
    )).toBeNull();
  });

  test('refuses a wrong message type or protocol version', () => {
    expect(readOrgSignWidgetRequest(
      { origin: 'https://app.example', source, data: { ...request, type: 'openkey:sign-out:request' } },
      'https://app.example',
      source,
    )).toBeNull();
    expect(readOrgSignWidgetRequest(
      { origin: 'https://app.example', source, data: { ...request, protocolVersion: 2 } },
      'https://app.example',
      source,
    )).toBeNull();
  });

  test('refuses empty or non-string requestId, keyId, and message', () => {
    for (const field of ['requestId', 'keyId', 'message'] as const) {
      expect(readOrgSignWidgetRequest(
        { origin: 'https://app.example', source, data: { ...request, [field]: '' } },
        'https://app.example',
        source,
      )).toBeNull();
      expect(readOrgSignWidgetRequest(
        { origin: 'https://app.example', source, data: { ...request, [field]: 7 } },
        'https://app.example',
        source,
      )).toBeNull();
    }
  });

  test('ignores a requesting origin supplied in the body', () => {
    const accepted = readOrgSignWidgetRequest(
      { origin: 'https://app.example', source, data: { ...request, requestingOrigin: 'https://evil.example' } },
      'https://app.example',
      source,
    );
    expect(accepted).not.toHaveProperty('requestingOrigin');
    expect(accepted?.keyId).toBe('key-1');
  });
});
