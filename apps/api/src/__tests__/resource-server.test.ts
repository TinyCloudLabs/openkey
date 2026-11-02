import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import {
  DEFAULT_RESOURCE_RATE_LIMIT_PER_MINUTE,
  MAX_RESOURCE_RATE_LIMIT_PER_MINUTE,
  clientSecretMatches,
  hashClientSecret,
  isCanonicalResourceUrl,
  readResourceServerPolicy,
  resourceServerMetadata,
  validateAllowedResources,
} from '../services/resource-server';

const MCP = 'https://mcp.tinycloud.xyz/mcp';
const CHATGPT_MCP = 'https://mcp.tinycloud.xyz/chatgpt/mcp';

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

describe('a registration for both MCP resources', () => {
  test('holds both, and reads back both', () => {
    expect(readResourceServerPolicy(resourceServerMetadata([MCP, CHATGPT_MCP]))).toEqual({ allowedResources: [MCP, CHATGPT_MCP] });
  });

  test('the chatgpt resource is refused, naming it, until the API lists it as an audience', () => {
    const problems = validateAllowedResources([MCP, CHATGPT_MCP], ['https://api.openkey.so', MCP]);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain(CHATGPT_MCP);
    expect(problems[0]).toContain('OAUTH_VALID_AUDIENCES');
    expect(validateAllowedResources([MCP, CHATGPT_MCP], ['https://api.openkey.so', MCP, CHATGPT_MCP])).toEqual([]);
  });
});

describe('the rate limit of a registration', () => {
  test('the default is 3000 a minute and the most a registration may ask for is 100000', () => {
    expect(DEFAULT_RESOURCE_RATE_LIMIT_PER_MINUTE).toBe(3000);
    expect(MAX_RESOURCE_RATE_LIMIT_PER_MINUTE).toBe(100_000);
  });

  test('is optional, and written and read back when set', () => {
    expect(readResourceServerPolicy(resourceServerMetadata([MCP]))).toEqual({ allowedResources: [MCP] });
    expect(readResourceServerPolicy(resourceServerMetadata([MCP], { rateLimitPerMinute: 6000 }))).toEqual({ allowedResources: [MCP], rateLimitPerMinute: 6000 });
    expect(readResourceServerPolicy(resourceServerMetadata([MCP], { rateLimitPerMinute: 1 }))?.rateLimitPerMinute).toBe(1);
    expect(readResourceServerPolicy(resourceServerMetadata([MCP], { rateLimitPerMinute: 100_000 }))?.rateLimitPerMinute).toBe(100_000);
  });

  test.each([0, -5, 1.5, 100_001, '3000', null, Number.NaN, Number.POSITIVE_INFINITY])('%p makes the client not a resource server', (value) => {
    expect(readResourceServerPolicy({ tinycloudResourceServer: { allowedResources: [MCP], rateLimitPerMinute: value } })).toBeNull();
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
