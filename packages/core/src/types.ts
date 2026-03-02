/**
 * Token response mapped to camelCase (what SDK consumers receive).
 */
export interface AuthTokens {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresIn: number;
}

/**
 * Raw OAuth token response from the server (snake_case).
 */
export interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  id_token: string;
  scope?: string;
  refresh_token?: string;
}
