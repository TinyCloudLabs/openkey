import type { AuthTokens } from './types';
import { OpenKeyError } from './errors';

// ======= Authorization URL =======

export interface BuildAuthorizationUrlOptions {
  /** OpenKey host URL (e.g. https://openkey.so) */
  host: string;
  /** OAuth client ID */
  clientId: string;
  /** Redirect URI for callback */
  redirectUri: string;
  /** PKCE code challenge (base64url-encoded) */
  codeChallenge: string;
  /** State parameter for CSRF protection */
  state: string;
  /** OAuth scopes to request */
  scopes: string[];
  /** Authorization endpoint path (default: /api/auth/oauth2/authorize) */
  authorizePath?: string;
}

/**
 * Build the OAuth 2.1 authorization URL with PKCE parameters.
 */
export function buildAuthorizationUrl(options: BuildAuthorizationUrlOptions): string {
  const {
    host,
    clientId,
    redirectUri,
    codeChallenge,
    state,
    scopes,
    authorizePath = '/api/auth/oauth2/authorize',
  } = options;

  const url = new URL(authorizePath, host);
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', scopes.join(' '));
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');

  return url.toString();
}

// ======= Token Exchange =======

export interface ExchangeCodeOptions {
  /** OpenKey host URL */
  host: string;
  /** Authorization code from callback */
  code: string;
  /** Redirect URI (must match authorization request) */
  redirectUri: string;
  /** OAuth client ID */
  clientId: string;
  /** PKCE code verifier */
  codeVerifier: string;
  /** RFC 9700 resource indicator (optional) */
  resource?: string;
  /** Token endpoint path (default: /api/auth/oauth2/token) */
  tokenPath?: string;
}

/**
 * Exchange an authorization code for tokens.
 */
export async function exchangeAuthorizationCode(
  options: ExchangeCodeOptions,
): Promise<AuthTokens> {
  const {
    host,
    code,
    redirectUri,
    clientId,
    codeVerifier,
    resource,
    tokenPath = '/api/auth/oauth2/token',
  } = options;

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: codeVerifier,
  });

  if (resource) {
    body.set('resource', resource);
  }

  let response: Response;
  try {
    response = await fetch(`${host}${tokenPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
  } catch (error) {
    throw new OpenKeyError(
      'NETWORK_ERROR',
      error instanceof Error ? error.message : 'Network request failed',
    );
  }

  if (!response.ok) {
    let detail = '';
    try {
      detail = await response.text();
    } catch {
      // ignore
    }
    throw new OpenKeyError(
      'UNKNOWN',
      `Token exchange failed: ${response.status} ${response.statusText}${detail ? ` - ${detail}` : ''}`,
    );
  }

  const data = (await response.json()) as Record<string, unknown>;
  return mapTokenResponse(data);
}

// ======= Token Refresh =======

export interface RefreshTokenOptions {
  /** OpenKey host URL */
  host: string;
  /** Refresh token */
  refreshToken: string;
  /** OAuth client ID */
  clientId: string;
  /** RFC 9700 resource indicator (optional) */
  resource?: string;
  /** Token endpoint path (default: /api/auth/oauth2/token) */
  tokenPath?: string;
}

/**
 * Refresh an access token using a refresh token.
 */
export async function refreshAccessToken(
  options: RefreshTokenOptions,
): Promise<AuthTokens> {
  const {
    host,
    refreshToken,
    clientId,
    resource,
    tokenPath = '/api/auth/oauth2/token',
  } = options;

  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId,
  });

  if (resource) {
    body.set('resource', resource);
  }

  let response: Response;
  try {
    response = await fetch(`${host}${tokenPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
  } catch (error) {
    throw new OpenKeyError(
      'NETWORK_ERROR',
      error instanceof Error ? error.message : 'Network request failed',
    );
  }

  if (!response.ok) {
    let detail = '';
    try {
      detail = await response.text();
    } catch {
      // ignore
    }
    throw new OpenKeyError(
      'UNKNOWN',
      `Token refresh failed: ${response.status} ${response.statusText}${detail ? ` - ${detail}` : ''}`,
    );
  }

  const data = (await response.json()) as Record<string, unknown>;
  return mapTokenResponse(data);
}

// ======= Helpers =======

/**
 * Map a snake_case token response to the camelCase AuthTokens interface.
 */
export function mapTokenResponse(data: Record<string, unknown>): AuthTokens {
  return {
    accessToken: data.access_token as string,
    idToken: data.id_token as string,
    refreshToken: data.refresh_token as string | undefined,
    expiresIn: data.expires_in as number,
  };
}

/**
 * Parse an OAuth callback URL and extract the code and state parameters.
 * Returns null if the URL doesn't contain the expected parameters.
 */
export function parseOAuthCallback(url: string): { code: string; state: string } | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  const code = parsed.searchParams.get('code');
  const state = parsed.searchParams.get('state');

  if (!code || !state) {
    return null;
  }

  return { code, state };
}
