// PKCE
export type { SHA256Fn } from './pkce';
export {
  base64UrlEncode,
  base64UrlDecode,
  sha256,
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
} from './pkce';

// Errors
export type { OpenKeyErrorCode } from './errors';
export { OpenKeyError } from './errors';

// Types
export type { AuthTokens, OAuthTokenResponse } from './types';

// OAuth
export type {
  BuildAuthorizationUrlOptions,
  ExchangeCodeOptions,
  RefreshTokenOptions,
} from './oauth';
export {
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  refreshAccessToken,
  mapTokenResponse,
  parseOAuthCallback,
} from './oauth';

// Native TinyCloud delegation (TC-774)
export type {
  OpenKeyNativeErrorCode,
  NativeFetch,
  NativeFetchInit,
  NativeFetchResponse,
  NativeSessionJwk,
  NativeDelegationPermission,
  TinyCloudDelegationRequest,
  TinyCloudDelegation,
  OpenKeyServerMetadata,
  NativeSessionKeypair,
  BuildParRequestOptions,
  PushedAuthorizationResponse,
  NativeCallbackResult,
  SessionProofOptions,
  ValidateDelegationOptions,
  ExchangeNativeCodeOptions,
  NativeTokenResult,
  RenewDelegationOptions,
  RenewDelegationResult,
  RevokeDelegationOptions,
  SleepFn,
} from './native-delegation';
export {
  OpenKeyNativeError,
  SESSION_PROOF_HEADER,
  SESSION_PROOF_TYP,
  DELEGATION_SCOPE,
  DEFAULT_DELEGATION_SCOPES,
  CAPABILITIES_READ_PERMISSION,
  generateNonce,
  sessionDidForPublicKey,
  generateSessionKeypair,
  sessionKeypairFromJwk,
  sessionJktForPublicJwk,
  discoveryUrlForIssuer,
  discoverOpenKeyServer,
  buildAuthorizationDetails,
  buildParRequest,
  sendParRequest,
  buildNativeAuthorizeUrl,
  parseNativeCallback,
  signSessionProof,
  isPermissionSubset,
  validateTinyCloudDelegation,
  exchangeDelegationCode,
  renewDelegation,
  revokeDelegation,
  parseRetryAfterSeconds,
  delegationNeedsRenewalNow,
} from './native-delegation';
