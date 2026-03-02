export type { AuthTokens, OpenKeyErrorCode } from '@openkey/core';
export { OpenKeyError } from '@openkey/core';

export interface OpenKeyRNConfig {
  host: string;
  clientId: string;
  redirectUri: string;
  /** RFC 9700 resource indicator. When set, access tokens are JWTs with this audience. Defaults to host URL. */
  resource?: string;
}
