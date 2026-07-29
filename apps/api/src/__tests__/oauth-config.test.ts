import { describe, expect, test } from 'bun:test';

import {
  DEFAULT_TINYCLOUD_MCP_AUDIENCE,
  DEFAULT_OAUTH_SCOPES,
  OAUTH_SCOPES,
  TINYCLOUD_SESSION_SCOPE,
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

  test('advertises tinycloud session delegation without defaulting it', () => {
    expect(OAUTH_SCOPES).toContain(TINYCLOUD_SESSION_SCOPE);
    expect(DEFAULT_OAUTH_SCOPES).not.toContain(TINYCLOUD_SESSION_SCOPE as never);
    expect(OAUTH_SCOPES).toContain('tinycloud:mcp');
    expect(DEFAULT_TINYCLOUD_MCP_AUDIENCE).toBe('https://mcp.tinycloud.xyz/mcp');
  });

  test('enables DCR by default and supports an explicit emergency disable', () => {
    expect(dynamicClientRegistrationEnabled(undefined)).toBe(true);
    expect(dynamicClientRegistrationEnabled('false')).toBe(false);
  });
});
