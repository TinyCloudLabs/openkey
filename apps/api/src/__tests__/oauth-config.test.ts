import { describe, expect, test } from 'bun:test';

import {
  DEFAULT_TINYCLOUD_MCP_AUDIENCE,
  OAUTH_SCOPES,
  dynamicClientRegistrationEnabled,
  oauthValidAudiences,
} from '../oauth-config';

describe('hosted MCP OAuth configuration', () => {
  test('allows the canonical resource and configured self-hosted resources', () => {
    expect(oauthValidAudiences('https://api.openkey.test', 'https://mcp.customer.test/mcp')).toEqual([
      'https://api.openkey.test',
      DEFAULT_TINYCLOUD_MCP_AUDIENCE,
      'https://mcp.customer.test/mcp',
    ]);
  });

  test('exposes the MCP scope without making it the only registration scope', () => {
    expect(OAUTH_SCOPES).toContain('tinycloud:mcp');
    expect(OAUTH_SCOPES).toContain('openid');
  });

  test('enables DCR by default and supports an explicit emergency disable', () => {
    expect(dynamicClientRegistrationEnabled(undefined)).toBe(true);
    expect(dynamicClientRegistrationEnabled('false')).toBe(false);
  });
});
