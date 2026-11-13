// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import { hostNamedByLink, originAuthority, requesterDisplayName } from './requester-display';

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

describe('host named by an unsigned link', () => {
  test.each([
    ['MCP.TinyCloud.XYZ', 'mcp.tinycloud.xyz'],
    ['localhost:47123', 'localhost:47123'],
    ['[::1]:47123', '[::1]:47123'],
    ['bücher.example', 'xn--bcher-kva.example'],
  ])('renders the full canonical authority for %s without an app alias', (input: string, host: string) => {
    expect(hostNamedByLink(input)).toBe(host);
  });

  test.each([
    undefined,
    'https://mcp.tinycloud.xyz',
    'owner@mcp.tinycloud.xyz',
    'mcp.tinycloud.xyz/path',
    'mcp.tinycloud.xyz?name=TinyCloud',
    'TinyCloud MCP',
  ])('does not turn a non-host claim into an identity: %s', (input: string | undefined) => {
    expect(hostNamedByLink(input)).toBe('an unknown site');
  });
});
