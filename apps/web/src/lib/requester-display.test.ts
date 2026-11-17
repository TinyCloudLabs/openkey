// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import { originAuthority, requesterDisplayName } from './requester-display';

describe('requester display safety', () => {
  test('uses a server-verified manifest name when available', () => {
    expect(requesterDisplayName('Listen', 'https://listen.example')).toBe('Listen');
  });

  test('falls back to the browser authority, including a non-default port', () => {
    expect(requesterDisplayName(null, 'https://listen.example:8443/path')).toBe(
      'listen.example:8443',
    );
    expect(originAuthority('https://listen.example:8443/path')).toBe(
      'listen.example:8443',
    );
  });

  test('does not invent a requester for an unattributed wildcard origin', () => {
    expect(requesterDisplayName(null, '*')).toBe('Unknown origin');
    expect(originAuthority('*')).toBeNull();
  });
});
