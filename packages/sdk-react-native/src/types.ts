export interface OpenKeyRNConfig {
  host: string;
  clientId: string;
  redirectUri: string;
  /** RFC 9700 resource indicator. When set, access tokens are JWTs with this audience. Defaults to host URL. */
  resource?: string;
}

export interface AuthTokens {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresIn: number;
}

export type OpenKeyErrorCode =
  | 'USER_CANCELLED'
  | 'TIMEOUT'
  | 'STATE_MISMATCH'
  | 'NETWORK_ERROR'
  | 'UNKNOWN';

export class OpenKeyError extends Error {
  constructor(
    public code: OpenKeyErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'OpenKeyError';
  }
}
