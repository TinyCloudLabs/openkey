export interface OpenKeyRNConfig {
  host: string;
  clientId: string;
  redirectUri: string;
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
