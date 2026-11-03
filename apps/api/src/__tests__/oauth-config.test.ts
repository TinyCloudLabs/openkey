import { describe, expect, test } from 'bun:test';

import {
  CHATGPT_TINYCLOUD_MCP_AUDIENCE,
  DEFAULT_ACCESS_TOKEN_EXPIRES_IN,
  DEFAULT_OAUTH_SCOPES,
  DEFAULT_TINYCLOUD_MCP_AUDIENCE,
  MCP_ACCESS_TOKEN_EXPIRES_IN,
  DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES,
  OAUTH_SCOPES,
  TINYCLOUD_MANAGE_KEY_SCOPE,
  TINYCLOUD_SESSION_SCOPE,
  accessTokenExpiresInFor,
  dynamicClientRegistrationEnabled,
} from '../oauth-config';

describe('hosted MCP OAuth configuration', () => {
  test('advertises tinycloud session delegation without defaulting it', () => {
    expect(OAUTH_SCOPES).toContain(TINYCLOUD_SESSION_SCOPE);
    expect(DEFAULT_OAUTH_SCOPES).not.toContain(TINYCLOUD_SESSION_SCOPE as never);
    expect(OAUTH_SCOPES).toContain('tinycloud:mcp');
  });

  test('advertises canonical-key management without making it a default scope', () => {
    expect(OAUTH_SCOPES).toContain(TINYCLOUD_MANAGE_KEY_SCOPE);
    expect(DEFAULT_OAUTH_SCOPES).not.toContain(TINYCLOUD_MANAGE_KEY_SCOPE as never);
    expect(DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES).not.toContain(TINYCLOUD_MANAGE_KEY_SCOPE);
  });

  test('enables DCR by default and supports an explicit emergency disable', () => {
    expect(dynamicClientRegistrationEnabled(undefined)).toBe(true);
    expect(dynamicClientRegistrationEnabled('false')).toBe(false);
  });
});

describe('accessTokenExpiresInFor (TC-1366)', () => {
  test('only a request for exactly one hosted MCP resource gets the long lifetime', () => {
    const long = MCP_ACCESS_TOKEN_EXPIRES_IN;
    for (const resource of [DEFAULT_TINYCLOUD_MCP_AUDIENCE, CHATGPT_TINYCLOUD_MCP_AUDIENCE, [CHATGPT_TINYCLOUD_MCP_AUDIENCE]]) {
      expect(accessTokenExpiresInFor(resource)).toBe(long);
    }
    for (const resource of [
      undefined, null, '', 'https://api.openkey.so', 'https://mcp.tinycloud.xyz/mcp/', 'https://mcp.tinycloud.xyz/chatgpt',
      'https://mcp.tinycloud.xyz/mcp?x=1', [], [DEFAULT_TINYCLOUD_MCP_AUDIENCE, 'https://api.openkey.so'],
      [DEFAULT_TINYCLOUD_MCP_AUDIENCE, CHATGPT_TINYCLOUD_MCP_AUDIENCE], 42, { resource: DEFAULT_TINYCLOUD_MCP_AUDIENCE },
    ]) {
      expect(accessTokenExpiresInFor(resource), JSON.stringify(resource)).toBe(DEFAULT_ACCESS_TOKEN_EXPIRES_IN);
    }
  });
});
