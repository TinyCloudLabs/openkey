export const TINYCLOUD_MCP_SCOPE = 'tinycloud:mcp';
export const TINYCLOUD_SESSION_SCOPE = 'tinycloud:session';
/**
 * Explicit consent for an OAuth client to ask OpenKey's TEE to sign a
 * structurally-valid TinyCloud SIWE/ReCap delegation with the user's
 * canonical managed identity. It is intentionally not a registration
 * default: clients must request it and users must see it at consent time.
 */
export const TINYCLOUD_MANAGE_KEY_SCOPE = 'tinycloud:manage-key';
export const TINYCLOUD_OWNER_DIDS_CLAIM = 'https://tinycloud.xyz/owner_dids';
export const TINYCLOUD_CANONICAL_IDENTITY_CLAIM =
  'https://tinycloud.xyz/canonical_identity';
export const DEFAULT_TINYCLOUD_MCP_AUDIENCE = 'https://mcp.tinycloud.xyz/mcp';

export const DEFAULT_OAUTH_SCOPES = ['openid', 'email', 'keys', 'offline_access'] as const;
export const OAUTH_SCOPES = [
  ...DEFAULT_OAUTH_SCOPES,
  TINYCLOUD_MCP_SCOPE,
  TINYCLOUD_SESSION_SCOPE,
  TINYCLOUD_MANAGE_KEY_SCOPE,
] as const;

// Dynamic registration only creates public clients. `tinycloud:manage-key`
// requires a pre-registered confidential client, so it cannot be requested by
// an unauthenticated dynamic registration.
export const DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES = OAUTH_SCOPES.filter(
  (scope) => scope !== TINYCLOUD_MANAGE_KEY_SCOPE,
);

export function oauthValidAudiences(baseURL: string, configured = process.env.OAUTH_VALID_AUDIENCES): string[] {
  const values = configured?.split(',').map((value) => value.trim()).filter(Boolean) ?? [];
  return Array.from(new Set([baseURL, DEFAULT_TINYCLOUD_MCP_AUDIENCE, ...values]));
}

export function dynamicClientRegistrationEnabled(
  configured = process.env.OAUTH_DYNAMIC_CLIENT_REGISTRATION,
): boolean {
  return configured?.trim().toLowerCase() !== 'false';
}
