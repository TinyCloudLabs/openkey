import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import {
  clientSecretMatches,
  hashClientSecret,
  isCanonicalResourceUrl,
  readResourceServerPolicy,
  resourceServerMetadata,
  validateAllowedResources,
} from '../services/resource-server';

const MCP = 'https://mcp.tinycloud.xyz/mcp';

describe('resource server registration in client metadata', () => {
  test('what is written is read back', () => {
    expect(readResourceServerPolicy(resourceServerMetadata([MCP, 'https://b.example/x']))).toEqual({ allowedResources: [MCP, 'https://b.example/x'] });
  });

  test('metadata stored as a JSON string is read the same way', () => {
    expect(readResourceServerPolicy(JSON.stringify(resourceServerMetadata([MCP])))).toEqual({ allowedResources: [MCP] });
  });

  test('duplicates collapse', () => {
    expect(readResourceServerPolicy(resourceServerMetadata([MCP, MCP]))).toEqual({ allowedResources: [MCP] });
  });

  test.each([
    ['null', null],
    ['no metadata', undefined],
    ['an unrelated object', { theme: 'dark' }],
    ['not JSON', '{nope'],
    ['an array', [resourceServerMetadata([MCP])]],
    ['a flag with no resources', { tinycloudResourceServer: {} }],
    ['an empty list', { tinycloudResourceServer: { allowedResources: [] } }],
    ['a non-list', { tinycloudResourceServer: { allowedResources: MCP } }],
    ['a non-string entry', { tinycloudResourceServer: { allowedResources: [MCP, 7] } }],
    ['an empty entry', { tinycloudResourceServer: { allowedResources: [MCP, ''] } }],
    ['a policy that is not an object', { tinycloudResourceServer: true }],
  ])('%s is not a resource server', (_name, metadata) => {
    expect(readResourceServerPolicy(metadata)).toBeNull();
  });
});

describe('resource URLs', () => {
  test.each([MCP, 'https://mcp.example/', 'https://host.example:8443/a/b'])('%s is canonical', (value) => {
    expect(isCanonicalResourceUrl(value)).toBe(true);
  });

  test.each([
    'http://mcp.tinycloud.xyz/mcp',
    'https://mcp.tinycloud.xyz',
    'https://MCP.tinycloud.xyz/mcp',
    'https://mcp.tinycloud.xyz/mcp?x=1',
    'https://mcp.tinycloud.xyz/mcp#frag',
    'https://user:pw@mcp.tinycloud.xyz/mcp',
    'https://mcp.tinycloud.xyz/a/../mcp',
    'mcp.tinycloud.xyz/mcp',
    '',
  ])('%p is not', (value) => {
    expect(isCanonicalResourceUrl(value)).toBe(false);
  });

  test('a registration may only name audiences the server issues tokens for', () => {
    const valid = ['https://api.openkey.so', MCP];
    expect(validateAllowedResources([MCP], valid)).toEqual([]);
    expect(validateAllowedResources([], valid)).toHaveLength(1);
    expect(validateAllowedResources(['https://other.example/mcp'], valid)).toHaveLength(1);
    expect(validateAllowedResources(['http://mcp.tinycloud.xyz/mcp', MCP], valid)).toHaveLength(1);
  });
});

describe('client secrets', () => {
  const secret = 'a-client-secret-0123456789-abcdefghijklmnop';
  const stored = hashClientSecret(secret);

  test('the stored form is the base64url SHA-256 the provider stores', () => {
    expect(stored).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(stored).toBe(new Bun.CryptoHasher('sha256').update(secret).digest('base64url'));
  });

  test('only the right secret matches', () => {
    expect(clientSecretMatches(secret, stored)).toBe(true);
    expect(clientSecretMatches(`${secret}x`, stored)).toBe(false);
    expect(clientSecretMatches('', stored)).toBe(false);
  });

  test.each([null, undefined, '', 'short', `${'x'.repeat(43)}`, `${'x'.repeat(44)}`])('%p as the stored value never matches', (value) => {
    expect(clientSecretMatches(secret, value)).toBe(false);
    expect(clientSecretMatches('', value)).toBe(false);
  });

  test('a plaintext stored value is not accepted in place of the hash', () => {
    expect(clientSecretMatches(secret, secret)).toBe(false);
  });
});
