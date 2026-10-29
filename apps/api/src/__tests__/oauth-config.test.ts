import { describe, expect, test } from 'bun:test';

import {
  DEFAULT_OAUTH_SCOPES,
  DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES,
  OAUTH_SCOPES,
  TINYCLOUD_MANAGE_KEY_SCOPE,
  TINYCLOUD_SESSION_SCOPE,
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
