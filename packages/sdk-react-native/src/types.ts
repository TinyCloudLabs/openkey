import type {
  AuthTokens,
  NativeDelegationPermission,
  NativeFetch,
  SleepFn,
  TinyCloudDelegation,
} from '@openkey/core';

export type { AuthTokens, OpenKeyErrorCode } from '@openkey/core';
export { OpenKeyError } from '@openkey/core';

/**
 * Secure key/value storage the app injects for TinyCloud delegation mode.
 * Back it with Expo SecureStore, react-native-keychain, MMKV with encryption,
 * or equivalent. The SDK stores the Ed25519 session private JWK and the
 * rotated refresh token under one key; everything written must be treated
 * as sensitive.
 */
export interface OpenKeySecureStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

/**
 * TinyCloud native-delegation options (docs/native-tinycloud-delegation.md).
 * When `delegation` is configured, `signIn()` runs the PAR + session-key
 * + proof flow from `@openkey/core` and resolves with
 * `{ tokens, delegation }`; `renew()` becomes available.
 */
export interface OpenKeyRNDelegationConfig {
  /** Requested capability entries; `tinycloud.capabilities/read` is added automatically. */
  permissions: NativeDelegationPermission[];
  /**
   * The TinyCloud node the app expects the delegation to target.
   * Exact-matched against the returned `tinycloudHost`; required.
   */
  tinycloudHost: string;
  /** Secure storage for the session key and rotated refresh token. */
  storage: OpenKeySecureStore;
  /** Delegation TTL in seconds (server clamps to the client ceiling). */
  ttlSeconds?: number;
  /** Optional SIWE nonce bound into the signed session SIWE. */
  siweNonce?: string;
  /** Injectable fetch for tests (defaults to global fetch). */
  fetchFn?: NativeFetch;
  /** Injectable sleep for Retry-After waits (defaults to setTimeout). */
  sleepFn?: SleepFn;
}

export interface OpenKeyRNConfig {
  host: string;
  clientId: string;
  redirectUri: string;
  /**
   * Expected authorization-server issuer (RFC 9207), checked against the
   * `iss` parameter on every callback. Defaults to `${host}/api/auth`.
   */
  issuer?: string;
  /**
   * OAuth scopes requested on sign-in.
   * Defaults to `['openid', 'email', 'keys', 'offline_access']`. In
   * delegation mode these are added to the mandatory
   * `openid offline_access tinycloud:delegation` set.
   */
  scopes?: string[];
  /**
   * RFC 8707 resource indicator. When set, access tokens are JWTs with this
   * audience. Not sent by default.
   */
  resource?: string;
  /** TinyCloud native-delegation mode. Omit for a plain OAuth sign-in. */
  delegation?: OpenKeyRNDelegationConfig;
}

/**
 * Tokens resolved by `signIn()`. In delegation mode `delegation` holds the
 * validated `tinycloud_delegation` payload; `idToken` is empty because the
 * native flow issues no ID token.
 */
export interface OpenKeyRNAuthTokens extends AuthTokens {
  delegation?: TinyCloudDelegation;
}
