import { describe, expect, test } from 'bun:test';

import {
  ADMIN_MANAGED_SCOPES,
  CHATGPT_TINYCLOUD_MCP_AUDIENCE,
  DEFAULT_ACCESS_TOKEN_EXPIRES_IN,
  DEFAULT_OAUTH_SCOPES,
  DEFAULT_TINYCLOUD_MCP_AUDIENCE,
  DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES,
  MCP_ACCESS_TOKEN_EXPIRES_IN,
  OAUTH_SCOPES,
  RESTRICTED_SCOPES,
  TINYCLOUD_IDENTITY_SCOPE,
  TINYCLOUD_MANAGE_KEY_SCOPE,
  TINYCLOUD_SESSION_SCOPE,
  accessTokenExpiresInFor,
  dynamicClientRegistrationEnabled,
  oauthValidAudiences,
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
  test('identity is admin-managed and excluded from public and dynamic scopes', () => {
    expect(OAUTH_SCOPES).toContain(TINYCLOUD_IDENTITY_SCOPE);
    expect(RESTRICTED_SCOPES.has(TINYCLOUD_IDENTITY_SCOPE)).toBe(true);
    expect(ADMIN_MANAGED_SCOPES.has(TINYCLOUD_IDENTITY_SCOPE)).toBe(true);
    expect(DEFAULT_OAUTH_SCOPES).not.toContain(TINYCLOUD_IDENTITY_SCOPE as never);
    expect(DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES).not.toContain(TINYCLOUD_IDENTITY_SCOPE);
  });

  test('enables DCR by default and supports an explicit emergency disable', () => {
    expect(dynamicClientRegistrationEnabled(undefined)).toBe(true);
    expect(dynamicClientRegistrationEnabled('false')).toBe(false);
  });
});

describe('oauthValidAudiences', () => {
  test('issues tokens for every hosted MCP address without configuration, and keeps configured extras', () => {
    expect(oauthValidAudiences('https://api.openkey.test', ' https://other.example/mcp ,')).toEqual([
      'https://api.openkey.test',
      'https://mcp.tinycloud.xyz/mcp',
      'https://mcp.tinycloud.xyz/chatgpt/mcp',
      'https://mcp.tinycloud.xyz/claude/mcp',
      'https://mcp.tinycloud.xyz/grok/mcp',
      'https://mcp.tinycloud.xyz/muse/mcp',
      'https://mcp.tinycloud.xyz/gemini/mcp',
      'https://mcp.tinycloud.xyz/perplexity/mcp',
      'https://mcp.tinycloud.xyz/mistral/mcp',
      'https://mcp.tinycloud.xyz/copilot/mcp',
      'https://other.example/mcp',
    ]);
  });
});

describe('accessTokenExpiresInFor (TC-1366)', () => {
  test('only a request for exactly one hosted MCP resource gets the long lifetime', () => {
    const long = MCP_ACCESS_TOKEN_EXPIRES_IN;
    for (const resource of [
      DEFAULT_TINYCLOUD_MCP_AUDIENCE, CHATGPT_TINYCLOUD_MCP_AUDIENCE, [CHATGPT_TINYCLOUD_MCP_AUDIENCE],
      'https://mcp.tinycloud.xyz/claude/mcp', 'https://mcp.tinycloud.xyz/grok/mcp', ['https://mcp.tinycloud.xyz/muse/mcp'],
      'https://mcp.tinycloud.xyz/gemini/mcp', ['https://mcp.tinycloud.xyz/perplexity/mcp'], 'https://mcp.tinycloud.xyz/mistral/mcp',
      'https://mcp.tinycloud.xyz/copilot/mcp',
    ]) {
      expect(accessTokenExpiresInFor(resource), JSON.stringify(resource)).toBe(long);
    }
    for (const resource of [
      undefined, null, '', 'https://api.openkey.so', 'https://mcp.tinycloud.xyz/mcp/', 'https://mcp.tinycloud.xyz/chatgpt',
      'https://mcp.tinycloud.xyz/claude', 'https://mcp.tinycloud.xyz/claude/mcp/', 'https://mcp.tinycloud.xyz/unlisted/mcp',
      'https://mcp.tinycloud.xyz/gemini', 'https://mcp.tinycloud.xyz/gemini/mcp/v2',
      'https://mcp.tinycloud.xyz/mcp?x=1', [], [DEFAULT_TINYCLOUD_MCP_AUDIENCE, 'https://api.openkey.so'],
      [DEFAULT_TINYCLOUD_MCP_AUDIENCE, CHATGPT_TINYCLOUD_MCP_AUDIENCE], 42, { resource: DEFAULT_TINYCLOUD_MCP_AUDIENCE },
    ]) {
      expect(accessTokenExpiresInFor(resource), JSON.stringify(resource)).toBe(DEFAULT_ACCESS_TOKEN_EXPIRES_IN);
    }
  });
});
