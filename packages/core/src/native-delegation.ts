import { sameTinyCloudHost } from './tinycloud-host';
import { recoverPersonalSignAddress } from './eth-signature';
/**
 * Native TinyCloud delegation flow (TC-774 task S1).
 *
 * Platform-agnostic protocol helpers for native sign-in that returns a
 * TinyCloud delegation: RFC 8414 discovery, PKCE/PAR, an Ed25519 session key
 * (did:key), the OpenKey-Session-Proof compact JWS, callback parsing, token
 * response validation, and typed clients for the token, renew and revoke
 * endpoints. Both `@openkey/sdk-capacitor` and `@openkey/sdk-react-native`
 * build on this module.
 * Wire shapes follow `docs/native-tinycloud-delegation.md` (the O1 spec,
 * normative for O2–O5 and TC-774):
 *   - PAR: `POST {metadata.pushed_authorization_request_endpoint}` (form)
 *   - Token: `POST {metadata.token_endpoint}` (form)
 *   - Renew: `POST {metadata.tinycloud_delegation_renew_endpoint}` (form)
 *   - Revoke: `POST {metadata.tinycloud_delegation_revocation_endpoint}` (form)
 *   - Proof header: `OpenKey-Session-Proof`; JWS `kid` is the session JWK's
 *     RFC 7638 thumbprint, compared to the stored `sessionJkt`.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { base64UrlEncode, base64UrlDecode, sha256, type SHA256Fn } from './pkce';

// ======= Errors =======

/** Error codes for the native delegation flow (spec "SDK mapping"). */
export type OpenKeyNativeErrorCode =
  | 'USER_CANCELLED'
  | 'ACCESS_DENIED'
  | 'STATE_MISMATCH'
  | 'CONSENT_REQUIRED'
  | 'INVALID_GRANT'
  | 'RENEWAL_CONFLICT'
  | 'RENEWAL_TOO_SOON'
  | 'SPACE_UNAVAILABLE'
  | 'INVALID_REQUEST'
  | 'TEMPORARILY_UNAVAILABLE'
  | 'NETWORK'
  | 'STORAGE'
  | 'SERVER'
  | 'NOT_SIGNED_IN'
  | 'UNAVAILABLE';

/** Error class for the native delegation flow. */
export class OpenKeyNativeError extends Error {
  constructor(
    public code: OpenKeyNativeErrorCode,
    message: string,
    /** HTTP status when the failure came from the authorization server. */
    public status?: number,
    /** The server's `error` field when it returned a JSON OAuth error. */
    public serverError?: string,
    /** `Retry-After` in whole seconds, when the server sent it (429/503). */
    public retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'OpenKeyNativeError';
  }

  /**
   * Set when a successful renew (or exchange) response was rejected after
   * the server already rotated the refresh token - delegation validation
   * or `hosting: "failed"`. The old token is dead; callers MUST persist
   * this value before reporting the error, or the session is lost.
   */
  public rotatedRefreshToken?: string;
}

// ======= Injectable fetch =======

/**
 * Minimal `fetch` parameter surface so a stub can satisfy the type without
 * implementing the full `RequestInit`/`Response` contract.
 */
export interface NativeFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface NativeFetchResponse {
  ok: boolean;
  status: number;
  /** Header lookup for `Retry-After`; case-insensitive like `Headers.get`. */
  headers?: { get(name: string): string | null };
  json(): Promise<unknown>;
}

export type NativeFetch = (
  url: string,
  init?: NativeFetchInit,
) => Promise<NativeFetchResponse>;

/** Sleep function, injectable for tests. */
export type SleepFn = (ms: number) => Promise<void>;

// Promise.withResolvers is newer than the ES2022 lib target and older
// Hermes; keep the executor form.
const defaultSleep: SleepFn = (ms) =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Parse a `Retry-After` header as whole seconds; `undefined` if absent/invalid. */
export function parseRetryAfterSeconds(
  value: string | null | undefined,
): number | undefined {
  if (value === null || value === undefined) return undefined;
  const seconds = Number.parseInt(value, 10);
  if (!Number.isFinite(seconds) || seconds < 0 || String(seconds) !== value.trim()) {
    return undefined;
  }
  return seconds;
}

// ======= Wire types =======

/** `session_key` JWK inside `authorization_details` (public half only). */
export interface NativeSessionJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid?: string;
}

/** One requested (or granted) TinyCloud capability entry. */
export interface NativeDelegationPermission {
  service: string;
  /** TinyCloud space; always `"applications"` for the current flow. */
  space: string;
  path?: string;
  actions: string[];
}

/** The `tinycloud_delegation` authorization-details element (PAR and renew). */
export interface TinyCloudDelegationRequest {
  type: 'tinycloud_delegation';
  session_key: NativeSessionJwk;
  permissions: NativeDelegationPermission[];
  ttl_seconds?: number;
  siwe_nonce?: string;
}

/**
 * The `tinycloud_delegation` object returned inside token and renew
 * responses. Field names mirror the server payload; `expiresAt` is accepted
 * as an ISO string or epoch seconds.
 */
export interface TinyCloudDelegation {
  version?: number;
  grantId?: string;
  address?: string;
  chainId?: number;
  ownerDid?: string;
  spaceId?: string;
  /** Verification method id — the session `did:key` with `#` fragment. */
  verificationMethod: string;
  siwe?: string;
  signature?: string;
  delegationHeader?: { Authorization: string };
  delegationCid?: string;
  issuedAt?: string;
  /** ISO timestamp or epoch seconds; must be in the future. */
  expiresAt: string | number;
  renewableUntil?: string | number;
  permissions: NativeDelegationPermission[];
  tinycloudHost: string;
  hosting?: 'existing' | 'created' | 'failed';
}

/** Validated RFC 8414 metadata for an OpenKey authorization server. */
export interface OpenKeyServerMetadata {
  /** The issuer URI exactly as configured (e.g. `https://api.openkey.so/api/auth`). */
  issuer: string;
  /** Origin of the issuer; endpoints are required to live on it. */
  origin: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  pushedAuthorizationRequestEndpoint: string;
  tinycloudDelegationRenewEndpoint: string;
  tinycloudDelegationRevocationEndpoint: string;
  /** `tinycloud_delegation_stepup_endpoint`; absent while the server's step-up switch is off. */
  tinycloudDelegationStepUpEndpoint?: string;
}

/** An Ed25519 session keypair plus its did:key and JWK serializations. */
export interface NativeSessionKeypair {
  /** `did:key:z…` (no fragment). */
  did: string;
  /**
   * Full verification-method id, `did:key:z…#z…`. This is the value the
   * server returns as `verificationMethod`. (The proof JWS `kid` is the
   * JWK's RFC 7638 thumbprint, not this value.)
   */
  keyId: string;
  /** Public JWK: `{kty: 'OKP', crv: 'Ed25519', x}` — the wire shape. */
  publicJwk: NativeSessionJwk;
  /** Private JWK: the public JWK plus `d`. */
  privateJwk: NativeSessionJwk & { d: string };
}

// ======= Constants =======

/** Header carrying the session-proof compact JWS. */
export const SESSION_PROOF_HEADER = 'OpenKey-Session-Proof';
export const SESSION_PROOF_TYP = 'openkey-session-proof+jwt';
export const DELEGATION_SCOPE = 'tinycloud:delegation';
/**
 * The permission entry every request must carry; the server refuses requests
 * without `tinycloud.capabilities/read`.
 */
export const CAPABILITIES_READ_PERMISSION: NativeDelegationPermission = {
  service: 'tinycloud.capabilities',
  space: 'applications',
  path: '',
  actions: ['tinycloud.capabilities/read'],
};
/** Scope set sent on PAR when no `extraScopes` are given. */
export const DEFAULT_DELEGATION_SCOPES = [
  'openid',
  'offline_access',
  DELEGATION_SCOPE,
];

// ======= Random helpers =======

/**
 * Generate a nonce for `siwe_nonce` / `jti`. Alphanumeric output satisfies
 * the SIWE nonce grammar `[A-Za-z0-9]{8,64}`.
 */
export function generateNonce(length = 32): string {
  const alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let nonce = '';
  for (const byte of bytes) nonce += alphabet[byte % alphabet.length]!;
  return nonce;
}

// ======= Ed25519 session keys =======

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58btcEncode(bytes: Uint8Array): string {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      carry += digits[index]! << 8;
      digits[index] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = '';
  for (const byte of bytes) {
    if (byte !== 0) break;
    output += BASE58_ALPHABET[0]!;
  }
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    output += BASE58_ALPHABET[digits[index]!]!;
  }
  return output;
}

/** `did:key` id for a raw Ed25519 public key: multicodec 0xed01 + base58btc. */
export function sessionDidForPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new OpenKeyNativeError(
      'SERVER',
      'Ed25519 public key must be 32 bytes',
    );
  }
  const identifier = `z${base58btcEncode(
    new Uint8Array([0xed, 0x01, ...publicKey]),
  )}`;
  return `did:key:${identifier}`;
}

/** Generate a fresh Ed25519 session keypair. */
export function generateSessionKeypair(): NativeSessionKeypair {
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  const did = sessionDidForPublicKey(publicKey);
  const keyId = `${did}#${did.slice('did:key:'.length)}`;
  const publicJwk: NativeSessionJwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: base64UrlEncode(publicKey),
  };
  return {
    did,
    keyId,
    publicJwk,
    privateJwk: { ...publicJwk, d: base64UrlEncode(secretKey) },
  };
}

/**
 * RFC 7638 JWK thumbprint of a session public JWK — the value the server
 * stores as `sessionJkt` and requires as the proof JWS `kid`.
 */
export async function sessionJktForPublicJwk(
  jwk: Pick<NativeSessionJwk, 'crv' | 'kty' | 'x'>,
  sha256Fn?: SHA256Fn,
): Promise<string> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return base64UrlEncode(await (sha256Fn ?? sha256)(canonical));
}

/**
 * Rebuild a `NativeSessionKeypair` from a persisted private JWK (d + x).
 * Verifies that `x` is the public key belonging to `d`.
 */
export function sessionKeypairFromJwk(
  privateJwk: NativeSessionJwk & { d: string },
): NativeSessionKeypair {
  const secretKey = base64UrlDecode(privateJwk.d);
  const publicKey = ed25519.getPublicKey(secretKey);
  const x = base64UrlEncode(publicKey);
  if (x !== privateJwk.x) {
    throw new OpenKeyNativeError(
      'SERVER',
      'session key JWK: x does not match d',
    );
  }
  const did = sessionDidForPublicKey(publicKey);
  const keyId = `${did}#${did.slice('did:key:'.length)}`;
  const publicJwk: NativeSessionJwk = { kty: 'OKP', crv: 'Ed25519', x };
  if (privateJwk.kid !== undefined) publicJwk.kid = privateJwk.kid;
  return {
    did,
    keyId,
    publicJwk,
    privateJwk,
  };
}

// ======= RFC 8414 discovery =======

/**
 * Build the metadata document URL for an issuer per RFC 8414 §3.1: the
 * `/.well-known/oauth-authorization-server` prefix is inserted between the
 * host and the issuer's path component.
 */
export function discoveryUrlForIssuer(issuer: string): string {
  const issuerUrl = new URL(issuer);
  const path = issuerUrl.pathname.replace(/\/+$/, '');
  return `${issuerUrl.origin}/.well-known/oauth-authorization-server${path}`;
}

const REQUIRED_ENDPOINTS = [
  'authorization_endpoint',
  'token_endpoint',
  'pushed_authorization_request_endpoint',
  'tinycloud_delegation_renew_endpoint',
  'tinycloud_delegation_revocation_endpoint',
] as const;

/**
 * Fetch and validate the authorization server metadata.
 *
 * Validation (plan §1.1): HTTPS issuer, `metadata.issuer === issuer`, and
 * every endpoint on the issuer's origin.
 */
export async function discoverOpenKeyServer(
  issuer: string,
  fetchFn: NativeFetch = fetch as unknown as NativeFetch,
): Promise<OpenKeyServerMetadata> {
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    throw new OpenKeyNativeError('SERVER', `issuer is not a URL: ${issuer}`);
  }
  if (issuerUrl.protocol !== 'https:') {
    throw new OpenKeyNativeError(
      'SERVER',
      `issuer must use https: ${issuer}`,
    );
  }

  const metadataUrl = discoveryUrlForIssuer(issuer);
  let response: NativeFetchResponse;
  try {
    response = await fetchFn(metadataUrl, { method: 'GET' });
  } catch (error) {
    throw new OpenKeyNativeError(
      'NETWORK',
      error instanceof Error ? error.message : 'Discovery request failed',
    );
  }
  if (!response.ok) {
    throw new OpenKeyNativeError(
      'SERVER',
      `Discovery failed: HTTP ${response.status}`,
      response.status,
    );
  }

  let metadata: Record<string, unknown>;
  try {
    metadata = (await response.json()) as Record<string, unknown>;
  } catch {
    throw new OpenKeyNativeError(
      'SERVER',
      'Discovery response is not JSON',
      response.status,
    );
  }

  if (metadata.issuer !== issuer) {
    throw new OpenKeyNativeError(
      'SERVER',
      `metadata issuer "${String(metadata.issuer)}" does not match "${issuer}"`,
    );
  }

  const endpointErrors: string[] = [];
  const endpoints: Record<(typeof REQUIRED_ENDPOINTS)[number], string> =
    {} as never;
  for (const field of REQUIRED_ENDPOINTS) {
    const value = metadata[field];
    if (typeof value !== 'string' || value.length === 0) {
      endpointErrors.push(`missing ${field}`);
      continue;
    }
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      endpointErrors.push(`${field} is not a URL`);
      continue;
    }
    if (url.origin !== issuerUrl.origin || url.protocol !== 'https:') {
      endpointErrors.push(`${field} is not on the issuer origin`);
      continue;
    }
    endpoints[field] = value;
  }
  if (endpointErrors.length > 0) {
    throw new OpenKeyNativeError(
      'SERVER',
      `Invalid server metadata: ${endpointErrors.join('; ')}`,
    );
  }

  // Optional: advertised only while the server's step-up switch is on.
  const stepUpEndpoint = metadata.tinycloud_delegation_stepup_endpoint;
  let tinycloudDelegationStepUpEndpoint: string | undefined;
  if (typeof stepUpEndpoint === 'string' && stepUpEndpoint.length > 0) {
    try {
      const url = new URL(stepUpEndpoint);
      if (url.origin === issuerUrl.origin && url.protocol === 'https:') {
        tinycloudDelegationStepUpEndpoint = stepUpEndpoint;
      }
    } catch {
      // An unusable advertisement is the same as none: step-up is unavailable.
    }
  }

  return {
    issuer,
    origin: issuerUrl.origin,
    authorizationEndpoint: endpoints.authorization_endpoint,
    tokenEndpoint: endpoints.token_endpoint,
    pushedAuthorizationRequestEndpoint:
      endpoints.pushed_authorization_request_endpoint,
    tinycloudDelegationRenewEndpoint:
      endpoints.tinycloud_delegation_renew_endpoint,
    tinycloudDelegationRevocationEndpoint:
      endpoints.tinycloud_delegation_revocation_endpoint,
    ...(tinycloudDelegationStepUpEndpoint
      ? { tinycloudDelegationStepUpEndpoint }
      : {}),
  };
}

// ======= authorization_details =======

/**
 * The exact permission array that goes on the wire: the caller's list with
 * `CAPABILITIES_READ_PERMISSION` prepended when missing. Subset validation
 * MUST run against this normalized array, not the raw caller list -
 * otherwise a server grant that includes `tinycloud.capabilities/read`
 * fails validation and a rotated refresh token is discarded.
 */
export function normalizeDelegationPermissions(
  permissions: NativeDelegationPermission[],
): NativeDelegationPermission[] {
  const hasCapabilitiesRead = permissions.some(
    (permission) =>
      permission.service === CAPABILITIES_READ_PERMISSION.service &&
      permission.actions.includes(CAPABILITIES_READ_PERMISSION.actions[0]!),
  );
  return hasCapabilitiesRead
    ? permissions
    : [CAPABILITIES_READ_PERMISSION, ...permissions];
}

/**
 * Build the `authorization_details` array for a `tinycloud_delegation`
 * request. Used for both PAR and renew. The mandatory
 * `tinycloud.capabilities/read` entry (`CAPABILITIES_READ_PERMISSION`) is
 * prepended when the caller's permissions do not already include it.
 */
export function buildAuthorizationDetails(options: {
  sessionKey: NativeSessionKeypair;
  permissions: NativeDelegationPermission[];
  ttlSeconds?: number;
  siweNonce?: string;
}): TinyCloudDelegationRequest[] {
  const detail: TinyCloudDelegationRequest = {
    type: 'tinycloud_delegation',
    session_key: options.sessionKey.publicJwk,
    permissions: normalizeDelegationPermissions(options.permissions),
  };
  if (options.ttlSeconds !== undefined) detail.ttl_seconds = options.ttlSeconds;
  if (options.siweNonce !== undefined) detail.siwe_nonce = options.siweNonce;
  return [detail];
}

// ======= PAR =======

/** Initial sign-in UX hint for OpenKey's login page; never an authorization input. */
export type NativeLoginMethod = 'email' | 'passkey' | 'google' | 'apple';
const NATIVE_LOGIN_METHODS: readonly string[] = ['email', 'passkey', 'google', 'apple'] satisfies NativeLoginMethod[];

export interface BuildParRequestOptions {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  sessionKey: NativeSessionKeypair;
  permissions: NativeDelegationPermission[];
  ttlSeconds?: number;
  siweNonce?: string;
  loginHint?: string;
  /** Only `email` (or no method) may carry `loginHint`. */
  loginMethod?: NativeLoginMethod;
  /** Extra scopes appended to `openid offline_access tinycloud:delegation`. */
  extraScopes?: string[];
}

/**
 * Build the form-encoded PAR body (spec: "Pushed authorization request").
 * The caller POSTs it to `metadata.pushedAuthorizationRequestEndpoint` —
 * the client cannot choose the host.
 */
export function buildParRequest(options: BuildParRequestOptions): {
  body: string;
  contentType: string;
} {
  const scopes = options.extraScopes
    ? [...DEFAULT_DELEGATION_SCOPES, ...options.extraScopes]
    : DEFAULT_DELEGATION_SCOPES;

  const form = new URLSearchParams();
  form.set('client_id', options.clientId);
  form.set('response_type', 'code');
  form.set('redirect_uri', options.redirectUri);
  form.set('state', options.state);
  form.set('code_challenge', options.codeChallenge);
  form.set('code_challenge_method', 'S256');
  form.set('scope', scopes.join(' '));
  form.set(
    'authorization_details',
    JSON.stringify(buildAuthorizationDetails(options)),
  );
  if (options.loginMethod !== undefined && !NATIVE_LOGIN_METHODS.includes(options.loginMethod)) {
    throw new OpenKeyNativeError('INVALID_REQUEST', 'Invalid login_method');
  }
  if (options.loginHint !== undefined) {
    const hint = options.loginHint.trim();
    if (hint.length > 254 || /[\s\p{C}]/u.test(hint) || (hint.match(/@/g) ?? []).length !== 1 ||
      hint.startsWith('@') || hint.endsWith('@') || (options.loginMethod !== undefined && options.loginMethod !== 'email')) {
      throw new OpenKeyNativeError('INVALID_REQUEST', 'Invalid login_hint');
    }
    form.set('login_hint', hint.toLowerCase());
  }
  if (options.loginMethod !== undefined) form.set('login_method', options.loginMethod);

  return {
    body: form.toString(),
    contentType: 'application/x-www-form-urlencoded',
  };
}

export interface PushedAuthorizationResponse {
  requestUri: string;
  expiresIn: number;
}

/**
 * POST the PAR body and validate the `201` response.
 */
export async function sendParRequest(
  metadata: OpenKeyServerMetadata,
  options: BuildParRequestOptions,
  fetchFn: NativeFetch = fetch as unknown as NativeFetch,
): Promise<PushedAuthorizationResponse> {
  const { body, contentType } = buildParRequest(options);
  const response = await postForm(
    metadata.pushedAuthorizationRequestEndpoint,
    body,
    contentType,
    fetchFn,
  );
  if (!response.ok) await throwEndpointError(response, 'PAR');
  const data = await readJson(response, 'PAR');
  const requestUri = data.request_uri;
  const expiresIn = data.expires_in;
  if (typeof requestUri !== 'string' || requestUri.length === 0) {
    throw new OpenKeyNativeError(
      'SERVER',
      'PAR response missing request_uri',
      response.status,
    );
  }
  return {
    requestUri,
    expiresIn: typeof expiresIn === 'number' ? expiresIn : 90,
  };
}

// ======= Authorize URL =======

/**
 * Build the authorization URL the app opens in ASWebAuthenticationSession /
 * a Custom Tab: `authorization_endpoint?client_id&request_uri`.
 */
export function buildNativeAuthorizeUrl(options: {
  authorizationEndpoint: string;
  clientId: string;
  requestUri: string;
}): string {
  const url = new URL(options.authorizationEndpoint);
  url.searchParams.set('client_id', options.clientId);
  url.searchParams.set('request_uri', options.requestUri);
  return url.toString();
}

// ======= Callback =======

export interface NativeCallbackResult {
  code: string;
  state: string;
  /** RFC 9207 issuer from the callback; verified equal to `issuer`. */
  iss: string;
}

/**
 * Parse the redirect callback URL.
 *
 * `iss` must equal the issuer (RFC 9207; the provider sends it on every
 * redirect, so a missing `iss` also fails) and `state` must match.
 * `error=access_denied` maps to `ACCESS_DENIED`; a state mismatch to
 * `STATE_MISMATCH`; a missing or wrong `iss` to `STATE_MISMATCH` too.
 */
export function parseNativeCallback(options: {
  url: string;
  expectedState: string;
  issuer: string;
}): NativeCallbackResult {
  let parsed: URL;
  try {
    parsed = new URL(options.url);
  } catch {
    throw new OpenKeyNativeError(
      'SERVER',
      // Never echo the callback URL - it may carry code/state.
      'Callback URL is not parseable',
    );
  }

  let params = parsed.searchParams;
  // Some redirect handlers deliver the response in the fragment.
  if (!params.has('code') && !params.has('error') && parsed.hash.length > 1) {
    const fragment = parsed.hash.startsWith('#')
      ? parsed.hash.slice(1)
      : parsed.hash;
    params = new URLSearchParams(fragment);
  }

  const iss = params.get('iss');
  if (!iss || iss !== options.issuer) {
    throw new OpenKeyNativeError(
      'STATE_MISMATCH',
      // Fixed message: iss is attacker-controlled and the URL carries
      // the auth code.
      'Callback iss does not match the issuer',
    );
  }

  const state = params.get('state');
  if (!state || state !== options.expectedState) {
    throw new OpenKeyNativeError(
      'STATE_MISMATCH',
      'Callback state does not match the pending request',
    );
  }

  const error = params.get('error');
  if (error) {
    const description = params.get('error_description') ?? undefined;
    throw mapOAuthError(error, description);
  }

  const code = params.get('code');
  if (!code) {
    throw new OpenKeyNativeError(
      'SERVER',
      'Callback has neither code nor error',
    );
  }

  return { code, state, iss };
}

/** Map an OAuth `error` value (callback or JSON error body) to a typed error. */
function mapOAuthError(
  error: string,
  description: string | undefined,
  status?: number,
  retryAfterSeconds?: number,
): OpenKeyNativeError {
  const message = description ? `${error}: ${description}` : error;
  switch (error) {
    case 'access_denied':
      return new OpenKeyNativeError('ACCESS_DENIED', message, status, error);
    case 'consent_required':
      return new OpenKeyNativeError('CONSENT_REQUIRED', message, status, error);
    case 'invalid_grant':
    case 'invalid_session_proof':
      // Terminal, never retried (spec SDK mapping).
      return new OpenKeyNativeError('INVALID_GRANT', message, status, error);
    case 'unauthorized':
      return new OpenKeyNativeError('NOT_SIGNED_IN', message, status, error);
    case 'renewal_conflict':
      return new OpenKeyNativeError('RENEWAL_CONFLICT', message, status, error);
    case 'space_unavailable':
      return new OpenKeyNativeError('SPACE_UNAVAILABLE', message, status, error);
    case 'renewal_too_soon':
      return new OpenKeyNativeError(
        'RENEWAL_TOO_SOON',
        message,
        status,
        error,
        retryAfterSeconds,
      );
    case 'temporarily_unavailable':
      return new OpenKeyNativeError(
        'TEMPORARILY_UNAVAILABLE',
        message,
        status,
        error,
        retryAfterSeconds,
      );
    default:
      return new OpenKeyNativeError('SERVER', message, status, error);
  }
}

// ======= Session proof JWS =======

export interface SessionProofOptions {
  sessionKey: NativeSessionKeypair;
  /** HTTP method of the request this proof authenticates (`htm`). */
  htm: string;
  /** Exact endpoint URL from metadata (`htu`). */
  htu: string;
  clientId: string;
  /** The credential being presented; hashed into `cred_hash`. */
  credential: string;
  /** For runtimes without Web Crypto. */
  sha256Fn?: SHA256Fn;
}

/**
 * Sign an `OpenKey-Session-Proof` compact JWS.
 *
 * Header: `{typ: "openkey-session-proof+jwt", alg: "EdDSA", kid}` where `kid`
 * is the RFC 7638 JWK thumbprint of the session public JWK — the value the
 * server stores as `sessionJkt` at PAR.
 * Payload: exactly `{jti, iat, htm, htu, client_id, cred_hash}` where
 * `cred_hash` is `b64url(sha256(credential))`.
 */
export async function signSessionProof(
  options: SessionProofOptions,
): Promise<string> {
  const hash = options.sha256Fn ?? sha256;
  const header = {
    typ: SESSION_PROOF_TYP,
    alg: 'EdDSA',
    kid: await sessionJktForPublicJwk(options.sessionKey.publicJwk, hash),
  };
  const payload = {
    jti: generateNonce(),
    iat: Math.floor(Date.now() / 1000),
    htm: options.htm,
    htu: options.htu,
    client_id: options.clientId,
    cred_hash: base64UrlEncode(await hash(options.credential)),
  };

  const encoder = new TextEncoder();
  const signingInput = `${base64UrlEncode(
    encoder.encode(JSON.stringify(header)),
  )}.${base64UrlEncode(encoder.encode(JSON.stringify(payload)))}`;

  const secretKey = base64UrlDecode(options.sessionKey.privateJwk.d);
  const signature = ed25519.sign(encoder.encode(signingInput), secretKey);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

// ======= Token response validation =======

function parseExpiresAt(value: string | number, field: string): number {
  if (typeof value === 'number') {
    // Seconds vs milliseconds heuristic: seconds values past ~2286 exceed 1e11.
    // Non-finite and non-positive values are malformed - reject (NaN <= now is
    // false and would otherwise pass the future check).
    if (!Number.isFinite(value) || value <= 0) {
      throw new OpenKeyNativeError(
        'SERVER',
        `tinycloud_delegation.${field} is not a valid epoch or ISO time`,
      );
    }
    return value > 1e11 ? value : value * 1000;
  }
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  throw new OpenKeyNativeError(
    'SERVER',
    `tinycloud_delegation.${field} is not a valid epoch or ISO time`,
  );
}

/** True when `grantedPath` is covered by `requestedPath` (prefix grants end in `/`). */
function pathCoveredBy(
  grantedPath: string | undefined,
  requestedPath: string | undefined,
): boolean {
  if (requestedPath === undefined || requestedPath === '') return true;
  if (grantedPath === undefined || grantedPath === '') return false;
  if (requestedPath.endsWith('/')) return grantedPath.startsWith(requestedPath);
  return grantedPath === requestedPath;
}

/** True when every granted permission is covered by a requested permission. */
export function isPermissionSubset(
  granted: NativeDelegationPermission[],
  requested: NativeDelegationPermission[],
): boolean {
  return granted.every((grant) =>
    requested.some(
      (request) =>
        request.service === grant.service &&
        request.space === grant.space &&
        pathCoveredBy(grant.path, request.path) &&
        grant.actions.every((action) => request.actions.includes(action)),
    ),
  );
}

function isPermission(value: unknown): value is NativeDelegationPermission {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const permission = value as Record<string, unknown>;
  return (
    typeof permission.service === 'string' &&
    typeof permission.space === 'string' &&
    (permission.path === undefined ||
      typeof permission.path === 'string') &&
    Array.isArray(permission.actions) &&
    permission.actions.every((action) => typeof action === 'string')
  );
}

export interface ValidateDelegationOptions {
  sessionKey: NativeSessionKeypair;
  /** The permission set sent in `authorization_details`, for the subset check. */
  requestedPermissions: NativeDelegationPermission[];
  /**
   * The TinyCloud node the client expects (spec: `tinycloudHost` must be
   * "the host it expects"). Required: validation fails closed without it.
   * The two production node names match; other hosts require exact equality.
   */
  expectedTinycloudHost: string;
}

/**
 * Validate the `tinycloud_delegation` object from a token or renew response:
 * `verificationMethod` equals the session DID, `expiresAt` is in the future,
 * permissions are a subset of what was requested, and `tinycloudHost` is an
 * https URL. Throws `OpenKeyNativeError` (code `SERVER`) on any violation.
 */
export function validateTinyCloudDelegation(
  value: unknown,
  options: ValidateDelegationOptions,
): TinyCloudDelegation {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new OpenKeyNativeError(
      'SERVER',
      'response missing tinycloud_delegation',
    );
  }
  const delegation = value as TinyCloudDelegation;

  if (delegation.verificationMethod !== options.sessionKey.keyId) {
    throw new OpenKeyNativeError(
      'SERVER',
      `verificationMethod "${String(
        delegation.verificationMethod,
      )}" does not match session key "${options.sessionKey.keyId}"`,
    );
  }

  if (delegation.expiresAt === undefined || delegation.expiresAt === null) {
    throw new OpenKeyNativeError(
      'SERVER',
      'tinycloud_delegation.expiresAt is missing',
    );
  }
  const expiresAt = parseExpiresAt(delegation.expiresAt, 'expiresAt');
  if (expiresAt <= Date.now()) {
    throw new OpenKeyNativeError(
      'SERVER',
      'tinycloud_delegation is already expired',
    );
  }

  if (!Array.isArray(delegation.permissions)) {
    throw new OpenKeyNativeError(
      'SERVER',
      'tinycloud_delegation.permissions is missing',
    );
  }
  if (!delegation.permissions.every(isPermission)) {
    throw new OpenKeyNativeError(
      'SERVER',
      'tinycloud_delegation.permissions has an invalid entry',
    );
  }
  if (
    !isPermissionSubset(delegation.permissions, options.requestedPermissions)
  ) {
    throw new OpenKeyNativeError(
      'SERVER',
      'granted permissions are not a subset of the requested permissions',
    );
  }

  if (
    typeof delegation.tinycloudHost !== 'string' ||
    delegation.tinycloudHost.length === 0
  ) {
    throw new OpenKeyNativeError(
      'SERVER',
      'tinycloud_delegation.tinycloudHost is missing',
    );
  }
  let host: URL;
  try {
    host = new URL(delegation.tinycloudHost);
  } catch {
    throw new OpenKeyNativeError(
      'SERVER',
      'tinycloud_delegation.tinycloudHost is not a URL',
    );
  }
  if (host.protocol !== 'https:' && host.hostname !== 'localhost') {
    throw new OpenKeyNativeError(
      'SERVER',
      `tinycloud_delegation.tinycloudHost must be https: ${delegation.tinycloudHost}`,
    );
  }
  if (
    typeof options.expectedTinycloudHost !== 'string' ||
    options.expectedTinycloudHost.length === 0
  ) {
    // Fail closed: the host check must not silently vanish.
    throw new OpenKeyNativeError(
      'SERVER',
      'expectedTinycloudHost is required to validate tinycloud_delegation',
    );
  }
  if (!sameTinyCloudHost(delegation.tinycloudHost, options.expectedTinycloudHost)) {
    throw new OpenKeyNativeError(
      'SERVER',
      `tinycloud_delegation.tinycloudHost "${delegation.tinycloudHost}" is not the expected host "${options.expectedTinycloudHost}"`,
    );
  }

  return delegation;
}

// ======= Endpoint clients =======

async function postForm(
  url: string,
  body: string,
  contentType: string,
  fetchFn: NativeFetch,
  headers?: Record<string, string>,
): Promise<NativeFetchResponse> {
  try {
    return await fetchFn(url, {
      method: 'POST',
      headers: { 'Content-Type': contentType, ...headers },
      body,
    });
  } catch (error) {
    throw new OpenKeyNativeError(
      'NETWORK',
      error instanceof Error ? error.message : 'Network request failed',
    );
  }
}

async function readJson(
  response: NativeFetchResponse,
  what: string,
): Promise<Record<string, unknown>> {
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new OpenKeyNativeError(
      'SERVER',
      `${what} response is not JSON (HTTP ${response.status})`,
      response.status,
    );
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new OpenKeyNativeError(
      'SERVER',
      `${what} response is not a JSON object (HTTP ${response.status})`,
      response.status,
    );
  }
  return data as Record<string, unknown>;
}

/** On a non-ok response, map the JSON `error` field, else a status error. */
async function throwEndpointError(
  response: NativeFetchResponse,
  what: string,
  /**
   * Extra `error` values this endpoint maps to INVALID_GRANT (spec SDK
   * table: provider code-exchange failures are terminal). Scoped to the
   * token endpoint - PAR emits `invalid_request`/`invalid_client` for
   * different causes, which stay SERVER.
   */
  invalidGrantErrors?: readonly string[],
): Promise<never> {
  const retryAfterSeconds = parseRetryAfterSeconds(
    response.headers?.get('Retry-After'),
  );
  try {
    const data = (await response.json()) as Record<string, unknown>;
    if (typeof data.error === 'string' && data.error.length > 0) {
      const description =
        typeof data.error_description === 'string'
          ? data.error_description
          : undefined;
      if (invalidGrantErrors?.includes(data.error)) {
        throw new OpenKeyNativeError(
          'INVALID_GRANT',
          description ? `${data.error}: ${description}` : data.error,
          response.status,
          data.error,
          retryAfterSeconds,
        );
      }
      throw mapOAuthError(
        data.error,
        description,
        response.status,
        retryAfterSeconds,
      );
    }
  } catch (error) {
    if (error instanceof OpenKeyNativeError) throw error;
    // fall through to status error
  }
  throw new OpenKeyNativeError(
    'SERVER',
    `${what} failed: HTTP ${response.status}`,
    response.status,
    undefined,
    retryAfterSeconds,
  );
}

// ----- Token exchange -----

export interface ExchangeNativeCodeOptions {
  metadata: OpenKeyServerMetadata;
  code: string;
  redirectUri: string;
  clientId: string;
  codeVerifier: string;
  sessionKey: NativeSessionKeypair;
  requestedPermissions: NativeDelegationPermission[];
  /** Expected TinyCloud node, accepting either production node name. Required - fails closed. */
  expectedTinycloudHost: string;
  fetchFn?: NativeFetch;
  sha256Fn?: SHA256Fn;
  /** Persist the issued refresh token before delegation validation or returning it. */
  onRefreshToken?: (refreshToken: string) => Promise<void>;
}

export interface NativeTokenResult {
  accessToken: string;
  refreshToken: string;
  /** `expires_in`: access-token lifetime (300 s per spec). */
  expiresIn?: number;
  /** `expires_at`: access-token expiry in Unix seconds, when present. */
  accessTokenExpiresAt?: number;
  /** Raw `authorization_details` echo from the server, if present. */
  authorizationDetails?: unknown;
  /** Validated `tinycloud_delegation` payload. */
  delegation: TinyCloudDelegation;
}

/**
 * Exchange an authorization code for tokens plus the TinyCloud delegation
 * (spec: "Code exchange"). Sends `OpenKey-Session-Proof` with `cred_hash =
 * b64url(sha256(code))` and validates the delegation in the response.
 *
 * Never retried: any failed exchange spends the code — including a 503 —
 * so errors surface to the caller, which must start a fresh sign-in.
 * A successful response with `hosting: "failed"` throws `SPACE_UNAVAILABLE`.
 */
export async function exchangeDelegationCode(
  options: ExchangeNativeCodeOptions,
): Promise<NativeTokenResult> {
  const fetchFn =
    options.fetchFn ?? (fetch as unknown as NativeFetch);
  const htu = options.metadata.tokenEndpoint;
  const proof = await signSessionProof({
    sessionKey: options.sessionKey,
    htm: 'POST',
    htu,
    clientId: options.clientId,
    credential: options.code,
    sha256Fn: options.sha256Fn,
  });

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: options.code,
    redirect_uri: options.redirectUri,
    client_id: options.clientId,
    code_verifier: options.codeVerifier,
  });

  const response = await postForm(
    htu,
    body.toString(),
    'application/x-www-form-urlencoded',
    fetchFn,
    { [SESSION_PROOF_HEADER]: proof },
  );
  if (!response.ok) {
    await throwEndpointError(response, 'Token exchange', [
      'invalid_request',
      'invalid_client',
      'invalid_verification',
    ]);
  }

  const data = await readJson(response, 'Token exchange');
  const issuedRefreshToken = typeof data.refresh_token === 'string' ? data.refresh_token : undefined;
  if (issuedRefreshToken) await options.onRefreshToken?.(issuedRefreshToken);
  if (
    typeof data.access_token !== 'string' ||
    typeof data.refresh_token !== 'string'
  ) {
    const error = new OpenKeyNativeError(
      'SERVER',
      'Token response missing access_token or refresh_token',
      response.status,
    );
    error.rotatedRefreshToken = issuedRefreshToken;
    throw error;
  }

  let delegation: TinyCloudDelegation;
  try {
    delegation = validateTinyCloudDelegation(
      data.tinycloud_delegation,
      {
        sessionKey: options.sessionKey,
        // Same normalized array sent on PAR - includes capabilities/read.
        requestedPermissions: normalizeDelegationPermissions(
          options.requestedPermissions,
        ),
        expectedTinycloudHost: options.expectedTinycloudHost,
      },
    );
    // hosting: "failed" means the delegation can't reach the space:
    // terminal for this session (spec SDK mapping -> SPACE_UNAVAILABLE).
    if (delegation.hosting === 'failed') {
      throw new OpenKeyNativeError(
        'SPACE_UNAVAILABLE',
        'Delegation was issued but hosting the applications space failed',
        response.status,
      );
    }
  } catch (error) {
    // The code was exchanged: tokens are live server-side. Surface the
    // refresh token so the caller can persist it rather than lose the
    // session (it is valid even though this delegation was rejected).
    if (error instanceof OpenKeyNativeError) {
      error.rotatedRefreshToken = data.refresh_token;
    }
    throw error;
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn:
      typeof data.expires_in === 'number' ? data.expires_in : undefined,
    accessTokenExpiresAt:
      typeof data.expires_at === 'number' ? data.expires_at : undefined,
    authorizationDetails: data.authorization_details,
    delegation,
  };
}

// ----- Renew -----

export interface RenewDelegationOptions {
  metadata: OpenKeyServerMetadata;
  clientId: string;
  refreshToken: string;
  sessionKey: NativeSessionKeypair;
  /** Permissions granted on the last delegation; used for the subset check. */
  requestedPermissions: NativeDelegationPermission[];
  /** Optional `siwe_nonce` form field (PAR rules: `[A-Za-z0-9]{8,64}`). */
  siweNonce?: string;
  /**
   * Optional permission subset sent as the `authorization_details` form
   * field (PAR shape, same session key, no `ttl_seconds`).
   */
  permissionsSubset?: NativeDelegationPermission[];
  /** Expected TinyCloud node, accepting either production node name. Required - fails closed. */
  expectedTinycloudHost: string;
  fetchFn?: NativeFetch;
  sha256Fn?: SHA256Fn;
  /** Injectable sleep for the spec-mandated `Retry-After` waits. */
  sleepFn?: SleepFn;
  /**
   * The step-ups this session holds, by app id (TC-3569). A renewed step-up is
   * validated against the held entry for its app; one for an app not held is
   * rejected.
   */
  heldStepUps?: Record<string, TinyCloudStepUp>;
}

export interface RenewDelegationResult {
  refreshToken: string;
  expiresIn?: number;
  delegation: TinyCloudDelegation;
  /** Step-up additions (TC-3569); present only when the server sent any. */
  stepUps?: NativeStepUpRenewal;
}

/**
 * Renew a delegation (spec: "Renewal"): `POST
 * {metadata.tinycloudDelegationRenewEndpoint}` as form-encoded
 * `client_id=…&refresh_token=…[&siwe_nonce=…][&authorization_details=…]`
 * with `OpenKey-Session-Proof` where `cred_hash =
 * b64url(sha256(refresh_token))`.
 *
 * Per the spec's SDK mapping: on 429 `renewal_too_soon` waits
 * `Retry-After` seconds and retries once with the same token (no generic
 * backoff); on 503 `temporarily_unavailable` waits `Retry-After` and
 * retries once with a fresh proof. `invalid_session_proof`,
 * `invalid_grant`, `consent_required` and `access_denied` are terminal and
 * never retried. `hosting: "failed"` throws `SPACE_UNAVAILABLE`.
 *
 * The server rotates the refresh token on every success. If validation of
 * the returned delegation fails afterwards, the thrown error carries
 * `rotatedRefreshToken`: the old token is dead, so the caller MUST persist
 * it before reporting the error or the session is lost.
 */
export async function renewDelegation(
  options: RenewDelegationOptions,
): Promise<RenewDelegationResult> {
  const fetchFn =
    options.fetchFn ?? (fetch as unknown as NativeFetch);
  const sleep = options.sleepFn ?? defaultSleep;
  const htu = options.metadata.tinycloudDelegationRenewEndpoint;

  // One normalized set: the exact array sent on the wire (including the
  // prepended capabilities/read) is what the grant is subset-checked
  // against - otherwise a 2xx renew that already rotated the refresh
  // token is rejected and the new token is lost.
  const requestedPermissions = normalizeDelegationPermissions(
    options.permissionsSubset ?? options.requestedPermissions,
  );
  // ttl_seconds; siwe_nonce travels as its own form field.
  const authorizationDetails = options.permissionsSubset
    ? buildAuthorizationDetails({
        sessionKey: options.sessionKey,
        permissions: options.permissionsSubset,
      })
    : undefined;

  const body = new URLSearchParams({
    client_id: options.clientId,
    refresh_token: options.refreshToken,
  });
  if (options.siweNonce !== undefined) {
    body.set('siwe_nonce', options.siweNonce);
  }
  if (authorizationDetails !== undefined) {
    body.set('authorization_details', JSON.stringify(authorizationDetails));
  }

  let retriedTooSoon = false;
  let retriedUnavailable = false;
  let response: NativeFetchResponse;
  for (;;) {
    // Fresh proof per attempt: `iat` must be within ±60 s.
    response = await postForm(
      htu,
      body.toString(),
      'application/x-www-form-urlencoded',
      fetchFn,
      {
        [SESSION_PROOF_HEADER]: await signSessionProof({
          sessionKey: options.sessionKey,
          htm: 'POST',
          htu,
          clientId: options.clientId,
          credential: options.refreshToken,
          sha256Fn: options.sha256Fn,
        }),
      },
    );
    if (response.ok) break;

    let thrown: unknown;
    try {
      await throwEndpointError(response, 'Renew');
    } catch (caught) {
      thrown = caught;
    }
    if (!(thrown instanceof OpenKeyNativeError)) throw thrown;

    if (thrown.code === 'RENEWAL_TOO_SOON' && !retriedTooSoon) {
      retriedTooSoon = true;
      // Wait Retry-After seconds; the spec guarantees ≥ 1.
      await sleep(Math.max(thrown.retryAfterSeconds ?? 1, 1) * 1000);
      continue;
    }
    if (thrown.code === 'TEMPORARILY_UNAVAILABLE' && !retriedUnavailable) {
      retriedUnavailable = true;
      await sleep(Math.max(thrown.retryAfterSeconds ?? 2, 1) * 1000);
      continue;
    }
    throw thrown;
  }

  const data = await readJson(response, 'Renew');
  if (typeof data.refresh_token !== 'string') {
    throw new OpenKeyNativeError(
      'SERVER',
      'Renew response missing refresh_token',
      response.status,
    );
  }

  let delegation: TinyCloudDelegation;
  try {
    delegation = validateTinyCloudDelegation(data.tinycloud_delegation, {
      sessionKey: options.sessionKey,
      requestedPermissions,
      expectedTinycloudHost: options.expectedTinycloudHost,
    });
    if (delegation.hosting === 'failed') {
      throw new OpenKeyNativeError(
        'SPACE_UNAVAILABLE',
        'Renewed delegation could not reach the applications space',
        response.status,
      );
    }
  } catch (error) {
    // The refresh token was already rotated: never discard it. Surface it
    // on the error so the caller can persist it before reporting.
    if (error instanceof OpenKeyNativeError) {
      error.rotatedRefreshToken = data.refresh_token;
    }
    throw error;
  }

  const stepUps = parseRenewedStepUps(data, options, delegation);
  return {
    refreshToken: data.refresh_token,
    expiresIn:
      typeof data.expires_in === 'number' ? data.expires_in : undefined,
    delegation,
    ...(stepUps ? { stepUps } : {}),
  };
}

// ----- Revoke -----

export interface RevokeDelegationOptions {
  metadata: OpenKeyServerMetadata;
  clientId: string;
  refreshToken: string;
  sessionKey: NativeSessionKeypair;
  fetchFn?: NativeFetch;
  sha256Fn?: SHA256Fn;
  /** Injectable sleep for the spec-mandated `Retry-After` wait. */
  sleepFn?: SleepFn;
}

/**
 * Revoke a grant (spec: "Native revocation"): `POST
 * {metadata.tinycloudDelegationRevocationEndpoint}` as form-encoded
 * `client_id=…&refresh_token=…` with `OpenKey-Session-Proof` where
 * `cred_hash = b64url(sha256(refresh_token))`.
 *
 * Per the spec's SDK mapping: on 503 `temporarily_unavailable` waits
 * `Retry-After` and retries once with the same token and a fresh proof.
 * `401 invalid_session_proof` (bad proof or unknown token) is terminal —
 * it maps to `INVALID_GRANT` and is never retried.
 *
 * Callers (SDK `signOut`): wipe the local session key and tokens even when
 * this rejects with a terminal error — per spec, a terminal revoke failure
 * means the server-side grant is already unusable. Core owns no storage,
 * so the wipe lives in the SDK layer.
 */
export async function revokeDelegation(
  options: RevokeDelegationOptions,
): Promise<void> {
  await postRevoke(options);
}

/** The revoke call, with `app_id` for one app's step-up (TC-3569) and without it for the grant. */
async function postRevoke(
  options: RevokeDelegationOptions,
  appId?: string,
): Promise<void> {
  const fetchFn =
    options.fetchFn ?? (fetch as unknown as NativeFetch);
  const sleep = options.sleepFn ?? defaultSleep;
  const htu = options.metadata.tinycloudDelegationRevocationEndpoint;
  const form = new URLSearchParams({
    client_id: options.clientId,
    refresh_token: options.refreshToken,
  });
  if (appId !== undefined) form.set('app_id', appId);
  const body = form.toString();

  let retriedUnavailable = false;
  for (;;) {
    const response = await postForm(
      htu,
      body,
      'application/x-www-form-urlencoded',
      fetchFn,
      {
        [SESSION_PROOF_HEADER]: await signSessionProof({
          sessionKey: options.sessionKey,
          htm: 'POST',
          htu,
          clientId: options.clientId,
          credential: options.refreshToken,
          sha256Fn: options.sha256Fn,
        }),
      },
    );
    if (response.ok) return;

    let thrown: unknown;
    try {
      await throwEndpointError(response, 'Revoke');
    } catch (caught) {
      thrown = caught;
    }
    if (!(thrown instanceof OpenKeyNativeError)) throw thrown;
    if (
      thrown.code === 'TEMPORARILY_UNAVAILABLE' &&
      !retriedUnavailable
    ) {
      retriedUnavailable = true;
      await sleep(Math.max(thrown.retryAfterSeconds ?? 2, 1) * 1000);
      continue;
    }
    throw thrown;
  }
}

// ======= Step-up (TC-3569) =======

/** The spaces a step-up may name; the server's `STEP_UP_SPACES`. */
export const NATIVE_STEP_UP_SPACES = ['public', 'account', 'agents', 'applications'] as const;

export type NativeStepUpSpace = (typeof NATIVE_STEP_UP_SPACES)[number];

/**
 * One step-up entry. Read-only: KV `get|list|metadata`, SQL `read|schema`.
 * `path` is always present (`""` is the whole space, admitted only in
 * `public`); for SQL it names one database.
 */
export interface NativeStepUpPermission extends NativeDelegationPermission {
  space: NativeStepUpSpace;
  path: string;
}

export interface NativeStepUpSpaceRef {
  space: NativeStepUpSpace;
  /** `tinycloud:pkh:eip155:<chainId>:<address>:<space>`. */
  spaceId: string;
}

/**
 * The signed step-up delegation: `tinycloud_stepup` in the code-exchange
 * response and one element of `tinycloud_stepups` in a renewal. It
 * mirrors the server's `stepUpDelegationResponse`; the delegate is always the
 * Home grant's own session key.
 */
export interface TinyCloudStepUp {
  version: 1;
  appId: string;
  /** The Home grant this step-up is bound to. */
  grantId: string;
  address: string;
  chainId: number;
  ownerDid: string;
  spaces: NativeStepUpSpaceRef[];
  /** Verification method id: the grant's session `did:key` with `#` fragment. */
  verificationMethod: string;
  siwe: string;
  signature: string;
  delegationHeader: { Authorization: string };
  delegationCid: string;
  issuedAt: string;
  expiresAt: string;
  /** The grant's renewal cutoff (its absolute expiry less 300 s). */
  renewableUntil: string;
  permissions: NativeStepUpPermission[];
  tinycloudHost: string;
  hosting: 'existing';
}

/** A renewed step-up the client refused; never fails Home's renewal. */
export interface NativeStepUpRejection {
  /** The app id the server named, when it was readable. */
  appId: string | null;
  message: string;
}

/**
 * The step-up additions of a renewal response. Present on a
 * `RenewDelegationResult` only when the server sent any of them.
 */
export interface NativeStepUpRenewal {
  /** `tinycloud_stepups`, each validated like a fresh step-up. */
  renewed: TinyCloudStepUp[];
  /** `tinycloud_stepups_dropped`: the ceiling no longer covers these; nothing was signed. */
  dropped: string[];
  /** `tinycloud_stepups_failed`: signing failed this time; the next renewal tries again. */
  failed: string[];
  /** `tinycloud_stepups_removed`: the app left the ceiling and its step-up ended. */
  removed: string[];
  /** Entries of `tinycloud_stepups` that failed client-side validation. */
  rejected: NativeStepUpRejection[];
}

const STEP_UP_APP_ID = /^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$/;
const STEP_UP_ENTRY_KEYS: readonly string[] = ['service', 'space', 'path', 'actions'];
const STEP_UP_ACTIONS: Record<string, readonly string[]> = {
  'tinycloud.kv': ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata'],
  'tinycloud.sql': ['tinycloud.sql/read', 'tinycloud.sql/schema'],
};
const MAX_STEP_UP_ENTRIES = 32;
/** The server's renewal cutoff: a grant is unusable 300 s before its absolute expiry. */
const GRANT_CUTOFF_MS = 300_000;

/** An app id as a framed app names itself: dotted ASCII, at most 128 characters. */
export function isNativeStepUpAppId(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 128 && STEP_UP_APP_ID.test(value);
}

/**
 * Parse a step-up entry list into fresh copies carrying exactly the four wire
 * members. `code` is `INVALID_REQUEST` for what the app asks and `SERVER` for
 * what the server returns.
 */
function parseStepUpPermissions(
  value: unknown,
  code: 'INVALID_REQUEST' | 'SERVER',
  label: string,
): NativeStepUpPermission[] {
  const fault = (message: string) => new OpenKeyNativeError(code, `${label}: ${message}`);
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_STEP_UP_ENTRIES) {
    throw fault(`expected 1 to ${MAX_STEP_UP_ENTRIES} entries`);
  }
  return value.map((item): NativeStepUpPermission => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw fault('entry is not an object');
    const entry = item as Record<string, unknown>;
    if (Object.keys(entry).some((key) => !STEP_UP_ENTRY_KEYS.includes(key))) {
      throw fault('entry has an unexpected member');
    }
    const { service, space, path, actions } = entry;
    if (typeof service !== 'string' || !Object.hasOwn(STEP_UP_ACTIONS, service)) {
      throw fault('service must be tinycloud.kv or tinycloud.sql');
    }
    if (typeof space !== 'string' || !(NATIVE_STEP_UP_SPACES as readonly string[]).includes(space)) {
      throw fault('space is not a step-up space');
    }
    if (typeof path !== 'string') throw fault('path must be a string');
    const allowed = STEP_UP_ACTIONS[service]!;
    if (
      !Array.isArray(actions) ||
      actions.length === 0 ||
      new Set(actions).size !== actions.length ||
      actions.some((action) => typeof action !== 'string' || !allowed.includes(action))
    ) {
      throw fault('actions must be unique read-only actions');
    }
    return { service, space: space as NativeStepUpSpace, path, actions: [...(actions as string[])] };
  });
}

/** Map the step-up endpoints' own error values onto the SDK's codes. */
function stepUpEndpointError(error: unknown, retryAfterSeconds?: number): unknown {
  if (!(error instanceof OpenKeyNativeError)) return error;
  switch (error.serverError) {
    case 'not_found':
      // The switch is off: the endpoint does not exist.
      return new OpenKeyNativeError('UNAVAILABLE', 'Step-up is not available on this OpenKey server', error.status, error.serverError);
    case 'invalid_request':
    case 'invalid_authorization_details':
      return new OpenKeyNativeError('INVALID_REQUEST', error.message, error.status, error.serverError);
    case 'slow_down':
      return new OpenKeyNativeError('TEMPORARILY_UNAVAILABLE', error.message, error.status, error.serverError, error.retryAfterSeconds ?? retryAfterSeconds);
    default:
      return error;
  }
}

export interface RequestStepUpOptions {
  metadata: OpenKeyServerMetadata;
  clientId: string;
  /** The Home grant's current refresh token. It is not rotated or consumed. */
  refreshToken: string;
  /** The Home grant's session key; the server reads the delegate from the grant, never from here. */
  sessionKey: NativeSessionKeypair;
  appId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  permissions: NativeStepUpPermission[];
  fetchFn?: NativeFetch;
  sha256Fn?: SHA256Fn;
  /** Injectable sleep for the `Retry-After` wait. */
  sleepFn?: SleepFn;
}

/**
 * Record a step-up request (spec: "Step-up request endpoint"): `POST
 * {metadata.tinycloudDelegationStepUpEndpoint}` as form-encoded `client_id,
 * refresh_token, app_id, permissions, redirect_uri, state, code_challenge,
 * code_challenge_method` with an `OpenKey-Session-Proof` over the refresh
 * token. It signs nothing and creates no grant. The returned `requestUri` is
 * opened with `buildNativeAuthorizeUrl`, as for sign-in.
 *
 * Throws `UNAVAILABLE` when the server does not offer step-up (no
 * discovery entry, or `404 not_found`) and `INVALID_REQUEST` for a malformed
 * request. Other refusals keep the usual codes (`ACCESS_DENIED`,
 * `CONSENT_REQUIRED`, `INVALID_GRANT`, ...). On `503` it waits `Retry-After` and
 * retries once with a fresh proof.
 */
export async function requestStepUp(
  options: RequestStepUpOptions,
): Promise<PushedAuthorizationResponse> {
  if (!isNativeStepUpAppId(options.appId)) {
    throw new OpenKeyNativeError('INVALID_REQUEST', 'Invalid step-up app id');
  }
  const permissions = parseStepUpPermissions(options.permissions, 'INVALID_REQUEST', 'step-up permissions');
  const htu = options.metadata.tinycloudDelegationStepUpEndpoint;
  if (!htu) {
    throw new OpenKeyNativeError('UNAVAILABLE', 'Step-up is not available on this OpenKey server');
  }
  const fetchFn = options.fetchFn ?? (fetch as unknown as NativeFetch);
  const sleep = options.sleepFn ?? defaultSleep;
  const body = new URLSearchParams({
    client_id: options.clientId,
    refresh_token: options.refreshToken,
    app_id: options.appId,
    permissions: JSON.stringify(permissions),
    redirect_uri: options.redirectUri,
    state: options.state,
    code_challenge: options.codeChallenge,
    code_challenge_method: 'S256',
  }).toString();

  let retriedUnavailable = false;
  let response: NativeFetchResponse;
  for (;;) {
    // Fresh proof per attempt: its `jti` is spent on first sight.
    response = await postForm(
      htu,
      body,
      'application/x-www-form-urlencoded',
      fetchFn,
      {
        [SESSION_PROOF_HEADER]: await signSessionProof({
          sessionKey: options.sessionKey,
          htm: 'POST',
          htu,
          clientId: options.clientId,
          credential: options.refreshToken,
          sha256Fn: options.sha256Fn,
        }),
      },
    );
    if (response.ok) break;

    let thrown: unknown;
    try {
      await throwEndpointError(response, 'Step-up request');
    } catch (caught) {
      thrown = caught;
    }
    if (!(thrown instanceof OpenKeyNativeError)) throw thrown;
    if (thrown.code === 'TEMPORARILY_UNAVAILABLE' && !retriedUnavailable) {
      retriedUnavailable = true;
      await sleep(Math.max(thrown.retryAfterSeconds ?? 2, 1) * 1000);
      continue;
    }
    throw stepUpEndpointError(thrown, parseRetryAfterSeconds(response.headers?.get('Retry-After')));
  }

  const data = await readJson(response, 'Step-up request');
  const requestUri = data.request_uri;
  if (typeof requestUri !== 'string' || requestUri.length === 0) {
    throw new OpenKeyNativeError(
      'SERVER',
      'Step-up request response missing request_uri',
      response.status,
    );
  }
  return {
    requestUri,
    expiresIn: typeof data.expires_in === 'number' ? data.expires_in : 90,
  };
}

/**
 * What Home's own delegation fixes for every step-up bound to its grant: the
 * grant id, the owner address and chain, and the grant's renewal cutoff.
 * Every field is required; a step-up is never checked against less.
 */
export interface NativeStepUpHomeBinding {
  /** The Home grant id, from its sign-in delegation. */
  expectedGrantId: string;
  /** The Home delegation's owner address; the step-up is signed by the same account. */
  expectedAddress: string;
  /** The Home delegation's chain id; the signed message names the same chain. */
  expectedChainId: number;
  /** The Home delegation's `renewableUntil`; a step-up never outlives its grant. */
  grantRenewableUntil: string | number;
}

/**
 * Read the binding out of Home's delegation. Throws `OpenKeyNativeError`
 * (`SERVER`) when it lacks the grant id, address, chain id or renewable-until
 * value: step-up fails closed rather than skip a check.
 */
export function nativeStepUpHomeBinding(delegation: TinyCloudDelegation): NativeStepUpHomeBinding {
  const { grantId, address, chainId, renewableUntil } = delegation;
  const missing: string[] = [];
  if (typeof grantId !== 'string' || grantId.length === 0) missing.push('grantId');
  if (typeof address !== 'string' || address.length === 0) missing.push('address');
  if (typeof chainId !== 'number' || !Number.isInteger(chainId) || chainId <= 0) missing.push('chainId');
  if (renewableUntil === undefined || renewableUntil === null || renewableUntil === '') missing.push('renewableUntil');
  if (
    missing.length > 0 ||
    typeof grantId !== 'string' || typeof address !== 'string' || typeof chainId !== 'number' || renewableUntil === undefined
  ) {
    throw new OpenKeyNativeError(
      'SERVER',
      `Home delegation lacks ${missing.join(', ')}; a step-up cannot be bound to it`,
    );
  }
  return { expectedGrantId: grantId, expectedAddress: address, expectedChainId: chainId, grantRenewableUntil: renewableUntil };
}

export interface ValidateStepUpOptions extends NativeStepUpHomeBinding {
  /** The Home grant's session key. */
  sessionKey: NativeSessionKeypair;
  /** The app the step-up was requested for. */
  appId: string;
  /** The entries sent on the request (or held, on renewal), for the subset check. */
  requestedPermissions: NativeStepUpPermission[];
  /** Expected TinyCloud node, accepting either production node name. Required - fails closed. */
  expectedTinycloudHost: string;
  /** Injectable clock (ms). */
  now?: number;
}

/** True when `host` is an https URL (or localhost) and the expected node. */
function checkStepUpHost(host: unknown, expected: string): string {
  const fault = (message: string) => new OpenKeyNativeError('SERVER', `tinycloud_stepup ${message}`);
  if (typeof host !== 'string' || host.length === 0) throw fault('tinycloudHost is missing');
  let url: URL;
  try {
    url = new URL(host);
  } catch {
    throw fault('tinycloudHost is not a URL');
  }
  if (url.protocol !== 'https:' && url.hostname !== 'localhost') {
    throw fault(`tinycloudHost must be https: ${host}`);
  }
  if (typeof expected !== 'string' || expected.length === 0) {
    // Fail closed: the host check must not silently vanish.
    throw fault('cannot be validated without expectedTinycloudHost');
  }
  if (!sameTinyCloudHost(host, expected)) {
    throw fault(`tinycloudHost "${host}" is not the expected host "${expected}"`);
  }
  return host;
}

function stepUpTime(value: unknown, field: string): number {
  const fault = () => new OpenKeyNativeError('SERVER', `tinycloud_stepup.${field} is not a valid ISO time`);
  if (typeof value !== 'string') throw fault();
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) throw fault();
  return parsed;
}

/**
 * Validate a `tinycloud_stepup` object from a code exchange or one element of
 * a renewal's `tinycloud_stepups`. It checks, in this order: the shape and
 * `version`; `appId`, `grantId`, the owner address and the chain id against
 * Home's delegation; the owner DID and each `spaceId` derived from the
 * address; that `verificationMethod` is the Home grant's session key;
 * read-only entries that are a subset of the ones requested, with exactly
 * their spaces; the SIWE text itself (the address line, exactly one `URI:`
 * line naming the session DID, exactly one `Chain ID:` line naming Home's
 * chain, exactly one `Expiration Time:` matching `expiresAt`) and that its
 * signature recovers to the owner address; the node host; and the lifetime
 * (in the future, after issue, never past the grant's cutoff). The SIWE
 * resources (the recap of the delegated abilities) are not decoded: the
 * entries and spaces are checked as the response lists them. Returns a clean
 * copy; throws `OpenKeyNativeError` (`SERVER`) on any violation. The TinyCloud
 * header and CID are checked by the SDK's WASM verifier, as for sign-in.
 */
export function validateTinyCloudStepUp(
  value: unknown,
  options: ValidateStepUpOptions,
): TinyCloudStepUp {
  const fault = (message: string) => new OpenKeyNativeError('SERVER', `tinycloud_stepup ${message}`);
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fault('is missing');
  }
  const raw = value as Record<string, unknown>;
  if (raw.version !== 1) throw fault('version is not supported');
  if (raw.appId !== options.appId) throw fault('appId does not match the request');
  const grantId = raw.grantId;
  if (typeof grantId !== 'string' || grantId.length === 0 || grantId !== options.expectedGrantId) {
    throw fault('grantId does not match the session grant');
  }
  const address = raw.address;
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw fault('address is invalid');
  }
  if (address.toLowerCase() !== options.expectedAddress.toLowerCase()) {
    throw fault('address does not match the session owner');
  }
  const chainId = options.expectedChainId;
  if (raw.chainId !== chainId) throw fault('chainId does not match the session grant');
  const ownerDid = raw.ownerDid;
  if (
    typeof ownerDid !== 'string' ||
    ownerDid.toLowerCase() !== `did:pkh:eip155:${chainId}:${address}`.toLowerCase()
  ) {
    throw fault('ownerDid does not match the address');
  }
  if (raw.verificationMethod !== options.sessionKey.keyId) {
    throw fault('verificationMethod does not match the session key');
  }
  if (raw.hosting !== 'existing') throw fault('hosting is not "existing"');

  const permissions = parseStepUpPermissions(raw.permissions, 'SERVER', 'tinycloud_stepup.permissions');
  if (!isPermissionSubset(permissions, options.requestedPermissions)) {
    throw fault('permissions are not a subset of the requested permissions');
  }
  const permissionSpaces = new Set(permissions.map((permission) => permission.space));
  const rawSpaces = raw.spaces;
  if (!Array.isArray(rawSpaces) || rawSpaces.length !== permissionSpaces.size) {
    throw fault('spaces do not match the permissions');
  }
  const spaces: NativeStepUpSpaceRef[] = [];
  const seenSpaces = new Set<string>();
  for (const item of rawSpaces) {
    const ref: Record<string, unknown> =
      item && typeof item === 'object' && !Array.isArray(item) ? item : {};
    const space = ref.space;
    if (
      typeof space !== 'string' ||
      !permissionSpaces.has(space as NativeStepUpSpace) ||
      seenSpaces.has(space) ||
      typeof ref.spaceId !== 'string' ||
      ref.spaceId.toLowerCase() !== `tinycloud:pkh:eip155:${chainId}:${address}:${space}`.toLowerCase()
    ) {
      throw fault('spaces do not match the permissions');
    }
    seenSpaces.add(space);
    spaces.push({ space: space as NativeStepUpSpace, spaceId: ref.spaceId });
  }

  const tinycloudHost = checkStepUpHost(raw.tinycloudHost, options.expectedTinycloudHost);

  const issuedMs = stepUpTime(raw.issuedAt, 'issuedAt');
  const expiresMs = stepUpTime(raw.expiresAt, 'expiresAt');
  const renewableMs = stepUpTime(raw.renewableUntil, 'renewableUntil');
  if (expiresMs <= (options.now ?? Date.now())) throw fault('is already expired');
  if (expiresMs <= issuedMs) throw fault('expires before it was issued');
  // The grant's absolute expiry is its renewal cutoff plus 300 s.
  if (expiresMs > renewableMs + GRANT_CUTOFF_MS) throw fault('outlives its grant');
  const grantMs = parseExpiresAt(options.grantRenewableUntil, 'renewableUntil');
  if (renewableMs > grantMs + 1000 || expiresMs > grantMs + GRANT_CUTOFF_MS) {
    throw fault('outlives the session grant');
  }

  const siwe = raw.siwe;
  const signature = raw.signature;
  if (typeof siwe !== 'string' || siwe.length === 0 || typeof signature !== 'string') {
    throw fault('is missing its signed message');
  }
  const sessionDid = options.sessionKey.keyId.split('#')[0]!;
  // The signed text is what the account actually authorized: bind it, not only the JSON beside it.
  const siweLines = siwe.split('\n');
  const siweField = (label: string): string | undefined => {
    const lines = siweLines.filter((line) => line.startsWith(`${label}: `));
    return lines.length === 1 ? lines[0]!.slice(label.length + 2) : undefined;
  };
  const siweExpiry = siweField('Expiration Time');
  if (
    siweLines[1]?.toLowerCase() !== address.toLowerCase() ||
    siweField('URI') !== sessionDid ||
    siweField('Chain ID') !== String(chainId) ||
    siweExpiry === undefined ||
    Math.abs(Date.parse(siweExpiry) - expiresMs) > 1000
  ) {
    throw fault('signed message does not match the delegation');
  }
  if (recoverPersonalSignAddress(siwe, signature) !== address.toLowerCase()) {
    throw fault('signature is not from the session owner');
  }

  const header = raw.delegationHeader;
  const authorization =
    header && typeof header === 'object' && !Array.isArray(header)
      ? (header as Record<string, unknown>).Authorization
      : undefined;
  if (typeof authorization !== 'string' || authorization.length === 0) {
    throw fault('delegationHeader is missing');
  }
  const delegationCid = raw.delegationCid;
  if (typeof delegationCid !== 'string' || delegationCid.length === 0) {
    throw fault('delegationCid is missing');
  }

  return {
    version: 1,
    appId: options.appId,
    grantId,
    address,
    chainId,
    ownerDid,
    spaces,
    verificationMethod: options.sessionKey.keyId,
    siwe,
    signature,
    delegationHeader: { Authorization: authorization },
    delegationCid,
    issuedAt: raw.issuedAt as string,
    expiresAt: raw.expiresAt as string,
    renewableUntil: raw.renewableUntil as string,
    permissions,
    tinycloudHost,
    hosting: 'existing',
  };
}

export interface ExchangeStepUpCodeOptions extends ValidateStepUpOptions {
  metadata: OpenKeyServerMetadata;
  code: string;
  /** The redirect URI sent on the step-up request. */
  redirectUri: string;
  clientId: string;
  codeVerifier: string;
  fetchFn?: NativeFetch;
  sha256Fn?: SHA256Fn;
}

/**
 * Redeem a step-up code (spec: "Step-up code exchange"): the sign-in token
 * call with the step-up request's redirect URI and a proof by the Home
 * grant's session key (`cred_hash` over the code). The response carries
 * `tinycloud_stepup` and nothing else of value: no refresh token and no
 * grant. A response that has either is refused. Never retried: the code is
 * spent even when this fails, so the app starts a new request.
 */
export async function exchangeStepUpCode(
  options: ExchangeStepUpCodeOptions,
): Promise<TinyCloudStepUp> {
  const fetchFn = options.fetchFn ?? (fetch as unknown as NativeFetch);
  const htu = options.metadata.tokenEndpoint;
  const proof = await signSessionProof({
    sessionKey: options.sessionKey,
    htm: 'POST',
    htu,
    clientId: options.clientId,
    credential: options.code,
    sha256Fn: options.sha256Fn,
  });
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: options.code,
    redirect_uri: options.redirectUri,
    client_id: options.clientId,
    code_verifier: options.codeVerifier,
  });

  const response = await postForm(
    htu,
    body.toString(),
    'application/x-www-form-urlencoded',
    fetchFn,
    { [SESSION_PROOF_HEADER]: proof },
  );
  if (!response.ok) {
    await throwEndpointError(response, 'Step-up exchange', [
      'invalid_request',
      'invalid_client',
      'invalid_verification',
    ]);
  }

  const data = await readJson(response, 'Step-up exchange');
  if (
    (data.refresh_token !== undefined && data.refresh_token !== null) ||
    (data.tinycloud_delegation !== undefined && data.tinycloud_delegation !== null)
  ) {
    // A step-up never mints a grant: this is not the response of a step-up.
    throw new OpenKeyNativeError(
      'SERVER',
      'Step-up response carries a refresh token or a grant',
      response.status,
    );
  }
  return validateTinyCloudStepUp(data.tinycloud_stepup, options);
}

export interface RevokeStepUpOptions extends RevokeDelegationOptions {
  appId: string;
}

/**
 * End one app's step-up (spec: "Revoking one app's step-up"): the native
 * revoke call with `app_id`. The grant, its refresh tokens and every other
 * app's step-up are untouched, and an app with no step-up also answers `200`.
 * Same retry and proof rules as `revokeDelegation`. Throws `UNAVAILABLE` when
 * the server refuses `app_id` because step-up is off.
 */
export async function revokeStepUp(options: RevokeStepUpOptions): Promise<void> {
  if (!isNativeStepUpAppId(options.appId)) {
    throw new OpenKeyNativeError('INVALID_REQUEST', 'Invalid step-up app id');
  }
  try {
    await postRevoke(options, options.appId);
  } catch (error) {
    throw stepUpEndpointError(error);
  }
}

/**
 * Read the step-up fields of a renewal response. Each `tinycloud_stepups`
 * element is validated like a fresh step-up against what this session holds
 * for that app; a malformed one is reported in `rejected` and never throws, so
 * Home's own renewal is never lost. `undefined` when the response has none of
 * the step-up fields.
 */
function parseRenewedStepUps(
  data: Record<string, unknown>,
  options: RenewDelegationOptions,
  delegation: TinyCloudDelegation,
): NativeStepUpRenewal | undefined {
  const fields = [
    'tinycloud_stepups',
    'tinycloud_stepups_dropped',
    'tinycloud_stepups_failed',
    'tinycloud_stepups_removed',
  ];
  if (fields.every((field) => data[field] === undefined)) return undefined;

  const appIds = (value: unknown): string[] =>
    Array.isArray(value) ? value.filter(isNativeStepUpAppId) : [];
  const held = options.heldStepUps ?? {};
  const renewed: TinyCloudStepUp[] = [];
  const rejected: NativeStepUpRejection[] = [];
  const seen = new Set<string>();
  // Home's renewed delegation is the reference every step-up is bound to; when it
  // lacks a field, no step-up can be checked, so each is rejected (never Home's renewal).
  let homeBinding: NativeStepUpHomeBinding | OpenKeyNativeError;
  try {
    homeBinding = nativeStepUpHomeBinding(delegation);
  } catch (error) {
    if (!(error instanceof OpenKeyNativeError)) throw error;
    homeBinding = error;
  }
  const items: unknown[] = Array.isArray(data.tinycloud_stepups) ? data.tinycloud_stepups : [];
  for (const item of items) {
    const named =
      item && typeof item === 'object' && !Array.isArray(item)
        ? (item as Record<string, unknown>).appId
        : undefined;
    const appId = isNativeStepUpAppId(named) ? named : null;
    try {
      if (appId === null) throw new OpenKeyNativeError('SERVER', 'tinycloud_stepup has no valid appId');
      const reference = Object.hasOwn(held, appId) ? held[appId] : undefined;
      if (!reference) {
        throw new OpenKeyNativeError('SERVER', 'tinycloud_stepup is for an app this session does not hold');
      }
      if (seen.has(appId)) throw new OpenKeyNativeError('SERVER', 'tinycloud_stepup is repeated');
      if (homeBinding instanceof OpenKeyNativeError) throw homeBinding;
      const stepUp = validateTinyCloudStepUp(item, {
        sessionKey: options.sessionKey,
        appId,
        requestedPermissions: reference.permissions,
        expectedTinycloudHost: options.expectedTinycloudHost,
        ...homeBinding,
      });
      seen.add(appId);
      renewed.push(stepUp);
    } catch (error) {
      rejected.push({
        appId,
        message: error instanceof OpenKeyNativeError ? error.message : 'tinycloud_stepup is invalid',
      });
    }
  }
  return {
    renewed,
    dropped: appIds(data.tinycloud_stepups_dropped),
    failed: appIds(data.tinycloud_stepups_failed),
    removed: appIds(data.tinycloud_stepups_removed),
    rejected,
  };
}

/**
 * True when the delegation should be renewed immediately — i.e. less than
 * the spec's renewal lead time remains on `expiresAt`. The lead is
 * `min(10 min, lifetime/4)` where `lifetime` comes from `issuedAt`; when
 * `issuedAt` is absent the full 10-minute lead is used. Call this after
 * sign-in (and on boot restore) to decide whether to renew now.
 */
export function delegationNeedsRenewalNow(
  delegation: Pick<TinyCloudDelegation, 'expiresAt' | 'issuedAt'>,
  now: number = Date.now(),
): boolean {
  const expiresAt = parseExpiresAt(delegation.expiresAt, 'expiresAt');
  const issuedAt =
    typeof delegation.issuedAt === 'string'
      ? Date.parse(delegation.issuedAt)
      : Number.NaN;
  const lifetimeMs =
    Number.isFinite(issuedAt) && issuedAt < expiresAt
      ? expiresAt - issuedAt
      : Number.POSITIVE_INFINITY;
  const leadMs = Math.min(10 * 60 * 1000, lifetimeMs / 4);
  return expiresAt - now < leadMs;
}
