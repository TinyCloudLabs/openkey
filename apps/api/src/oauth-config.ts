export const TINYCLOUD_MCP_SCOPE = 'tinycloud:mcp';
export const TINYCLOUD_OWNER_DIDS_CLAIM = 'https://tinycloud.xyz/owner_dids';
export const DEFAULT_TINYCLOUD_MCP_AUDIENCE = 'https://mcp.tinycloud.xyz/mcp';

export const DEFAULT_OAUTH_SCOPES = ['openid', 'email', 'keys', 'offline_access'] as const;
export const OAUTH_SCOPES = [...DEFAULT_OAUTH_SCOPES, TINYCLOUD_MCP_SCOPE] as const;

export function oauthValidAudiences(baseURL: string, configured = process.env.OAUTH_VALID_AUDIENCES): string[] {
  const values = configured?.split(',').map((value) => value.trim()).filter(Boolean) ?? [];
  return Array.from(new Set([baseURL, DEFAULT_TINYCLOUD_MCP_AUDIENCE, ...values]));
}

export function dynamicClientRegistrationEnabled(
  configured = process.env.OAUTH_DYNAMIC_CLIENT_REGISTRATION,
): boolean {
  return configured?.trim().toLowerCase() !== 'false';
}
