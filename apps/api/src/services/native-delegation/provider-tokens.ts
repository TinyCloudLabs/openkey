import { createHash } from 'node:crypto';

/**
 * Token normalization of @better-auth/oauth-provider 1.6.10, driven by the
 * provider's own configured options. The provider does not export
 * `decodeRefreshToken` or `getStoredToken`; these mirror them step for step
 * (`dist/index.mjs` `decodeRefreshToken`, the opaque access-token prefix
 * handling in `revokeOpaqueAccessToken`, and `getStoredToken` in its utils
 * chunk). The package is pinned exactly, and the integration tests check
 * that every token the provider finds is found here too.
 */

type StoredTokenType = 'refresh_token' | 'access_token';

export interface ProviderTokenOptions {
  prefix?: { refreshToken?: string; opaqueAccessToken?: string };
  formatRefreshToken?: {
    decrypt?: (token: string) => { token: string } | Promise<{ token: string }>;
  };
  storeTokens?: unknown;
}

/** The options object of the oauth-provider plugin instance actually in use. */
export function providerTokenOptions(auth: { options: { plugins?: unknown[] } }): ProviderTokenOptions {
  const plugin = auth.options.plugins?.find(
    (candidate): candidate is { id: string; options: ProviderTokenOptions } =>
      typeof candidate === 'object' && candidate !== null && (candidate as { id?: unknown }).id === 'oauth-provider',
  );
  if (!plugin?.options) throw new Error('oauth-provider plugin is not configured');
  return plugin.options;
}

async function storedToken(options: ProviderTokenOptions, token: string, type: StoredTokenType): Promise<string> {
  const method = options.storeTokens ?? 'hashed';
  // `defaultHasher`: unpadded base64url SHA-256.
  if (method === 'hashed') return createHash('sha256').update(token).digest('base64url');
  if (typeof method === 'object' && method !== null && 'hash' in method &&
      typeof (method as { hash: unknown }).hash === 'function') {
    return (method as { hash: (token: string, type: StoredTokenType) => string | Promise<string> }).hash(token, type);
  }
  throw new Error(`unsupported oauth-provider storeTokens method: ${String(method)}`);
}

/**
 * The stored value the provider looks a refresh token up by, or null when the
 * provider would reject the token before any lookup (prefix mismatch).
 */
export async function storedRefreshToken(options: ProviderTokenOptions, token: string): Promise<string | null> {
  let value = token;
  const prefix = options.prefix?.refreshToken;
  if (prefix) {
    if (!value.startsWith(prefix)) return null;
    value = value.replace(prefix, '');
  }
  const decoded = options.formatRefreshToken?.decrypt ? await options.formatRefreshToken.decrypt(value) : { token: value };
  return storedToken(options, decoded.token, 'refresh_token');
}

/** The stored value the provider looks an opaque access token up by, or null. */
export async function storedOpaqueAccessToken(options: ProviderTokenOptions, token: string): Promise<string | null> {
  let value = token;
  const prefix = options.prefix?.opaqueAccessToken;
  if (prefix) {
    if (!value.startsWith(prefix)) return null;
    value = value.replace(prefix, '');
  }
  return storedToken(options, value, 'access_token');
}
