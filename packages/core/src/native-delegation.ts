/**
 * Native TinyCloud delegation flow (TC-774 task S1).
 *
 * Platform-agnostic protocol helpers for native sign-in that returns a
 * TinyCloud delegation: RFC 8414 discovery, PKCE/PAR, an Ed25519 session key
 * (did:key), the OpenKey-Session-Proof compact JWS, callback parsing, token
 * response validation, and typed clients for the token, renew and revoke
 * endpoints. Both `@openkey/sdk-capacitor` and `@openkey/sdk-react-native`
 * build on this module.
 *
 * Wire shapes follow `tc773-plan-v3.md` §1:
 *   - PAR: `POST {metadata.pushed_authorization_request_endpoint}`
 *   - Token: `POST {metadata.token_endpoint}`
 *   - Renew: `POST {metadata.tinycloud_delegation_renew_endpoint}` (JSON)
 *   - Revoke: `POST {metadata.tinycloud_delegation_revocation_endpoint}` (JSON)
 *   - Proof header: `OpenKey-Session-Proof`
 */

import { ed25519 } from '@noble/curves/ed25519';
import { base64UrlEncode, base64UrlDecode, sha256, type SHA256Fn } from './pkce';

// ======= Errors =======

/** Error codes for the native delegation flow. */
export type OpenKeyNativeErrorCode =
  | 'USER_CANCELLED'
  | 'ACCESS_DENIED'
  | 'STATE_MISMATCH'
  | 'ISSUER_MISMATCH'
  | 'CONSENT_REQUIRED'
  | 'INVALID_GRANT'
  | 'RENEWAL_CONFLICT'
  | 'SPACE_UNAVAILABLE'
  | 'TEMPORARILY_UNAVAILABLE'
  | 'NETWORK'
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
  ) {
    super(message);
    this.name = 'OpenKeyNativeError';
  }
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
  json(): Promise<unknown>;
}

export type NativeFetch = (
  url: string,
  init?: NativeFetchInit,
) => Promise<NativeFetchResponse>;

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
  delegationHeader?: string;
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
}

/** An Ed25519 session keypair plus its did:key and JWK serializations. */
export interface NativeSessionKeypair {
  /** `did:key:z…` (no fragment). */
  did: string;
  /**
   * Full verification-method id, `did:key:z…#z…`. This is the value the
   * server stores for `verificationMethod` and the JWS `kid`.
   */
  keyId: string;
  /** Public JWK: `{kty: 'OKP', crv: 'Ed25519', x, kid}`. `kid` is `keyId`. */
  publicJwk: NativeSessionJwk;
  /** Private JWK: the public JWK plus `d`. */
  privateJwk: NativeSessionJwk & { d: string };
}

// ======= Constants =======

/** Header carrying the session-proof compact JWS. */
export const SESSION_PROOF_HEADER = 'OpenKey-Session-Proof';
export const SESSION_PROOF_TYP = 'openkey-session-proof+jwt';
export const DELEGATION_SCOPE = 'tinycloud:delegation';
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
    kid: keyId,
  };
  return {
    did,
    keyId,
    publicJwk,
    privateJwk: { ...publicJwk, d: base64UrlEncode(secretKey) },
  };
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
  return {
    did,
    keyId,
    publicJwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x,
      kid: privateJwk.kid ?? keyId,
    },
    privateJwk: { ...privateJwk, kid: privateJwk.kid ?? keyId },
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
      'ISSUER_MISMATCH',
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
  };
}

// ======= authorization_details =======

/**
 * Build the `authorization_details` array for a `tinycloud_delegation`
 * request. Used for both PAR and renew.
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
    permissions: options.permissions,
  };
  if (options.ttlSeconds !== undefined) detail.ttl_seconds = options.ttlSeconds;
  if (options.siweNonce !== undefined) detail.siwe_nonce = options.siweNonce;
  return [detail];
}

// ======= PAR =======

export interface BuildParRequestOptions {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  sessionKey: NativeSessionKeypair;
  permissions: NativeDelegationPermission[];
  ttlSeconds?: number;
  siweNonce?: string;
  /** Extra scopes appended to `openid offline_access tinycloud:delegation`. */
  extraScopes?: string[];
}

/**
 * Build the form-encoded PAR body (plan §1.1 step 2). The caller POSTs it to
 * `metadata.pushedAuthorizationRequestEndpoint` — the client cannot choose
 * the host.
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
 * `STATE_MISMATCH`; a missing or wrong `iss` to `ISSUER_MISMATCH`.
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
      `Callback URL is not parseable: ${options.url}`,
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
      'ISSUER_MISMATCH',
      `Callback iss "${iss ?? '(missing)'}" does not match issuer "${options.issuer}"`,
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
  description?: string,
  status?: number,
): OpenKeyNativeError {
  const message = description ? `${error}: ${description}` : error;
  switch (error) {
    case 'access_denied':
      return new OpenKeyNativeError('ACCESS_DENIED', message, status, error);
    case 'consent_required':
      return new OpenKeyNativeError(
        'CONSENT_REQUIRED',
        message,
        status,
        error,
      );
    case 'invalid_grant':
    case 'invalid_session_proof':
      return new OpenKeyNativeError('INVALID_GRANT', message, status, error);
    case 'renewal_conflict':
      return new OpenKeyNativeError('RENEWAL_CONFLICT', message, status, error);
    case 'space_unavailable':
      return new OpenKeyNativeError(
        'SPACE_UNAVAILABLE',
        message,
        status,
        error,
      );
    case 'temporarily_unavailable':
      return new OpenKeyNativeError(
        'TEMPORARILY_UNAVAILABLE',
        message,
        status,
        error,
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
  siweNonce?: string;
  /** Optional permission subset (renew). Serialized into `authorization_details`. */
  authorizationDetails?: TinyCloudDelegationRequest[];
  /** For runtimes without Web Crypto. */
  sha256Fn?: SHA256Fn;
}

/**
 * Sign an `OpenKey-Session-Proof` compact JWS.
 *
 * Header: `{typ: "openkey-session-proof+jwt", alg: "EdDSA", kid}` where `kid`
 * is the did:key verification-method id (`did:key:z…#z…`).
 * Payload: `{jti, iat, htm, htu, client_id, cred_hash}` where `cred_hash` is
 * `b64url(sha256(credential))`, plus optional `siwe_nonce` and
 * `authorization_details`.
 */
export async function signSessionProof(
  options: SessionProofOptions,
): Promise<string> {
  const header = {
    typ: SESSION_PROOF_TYP,
    alg: 'EdDSA',
    kid: options.sessionKey.keyId,
  };
  const payload: Record<string, unknown> = {
    jti: generateNonce(),
    iat: Math.floor(Date.now() / 1000),
    htm: options.htm,
    htu: options.htu,
    client_id: options.clientId,
    cred_hash: base64UrlEncode(
      await (options.sha256Fn ?? sha256)(options.credential),
    ),
  };
  if (options.siweNonce !== undefined) payload.siwe_nonce = options.siweNonce;
  if (options.authorizationDetails !== undefined) {
    payload.authorization_details = options.authorizationDetails;
  }

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
    return value > 1e11 ? value : value * 1000;
  }
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  throw new OpenKeyNativeError(
    'SERVER',
    `tinycloud_delegation.${field} is not a timestamp`,
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
): Promise<never> {
  try {
    const data = (await response.json()) as Record<string, unknown>;
    if (typeof data.error === 'string' && data.error.length > 0) {
      throw mapOAuthError(
        data.error,
        typeof data.error_description === 'string'
          ? data.error_description
          : undefined,
        response.status,
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
  fetchFn?: NativeFetch;
  sha256Fn?: SHA256Fn;
}

export interface NativeTokenResult {
  accessToken: string;
  refreshToken: string;
  expiresIn?: number;
  /** Raw `authorization_details` echo from the server, if present. */
  authorizationDetails?: unknown;
  delegation: TinyCloudDelegation;
}

/**
 * Exchange an authorization code for tokens plus the TinyCloud delegation
 * (plan §1.1b). Sends `OpenKey-Session-Proof` with `cred_hash =
 * b64url(sha256(code))` and validates the delegation in the response.
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
  if (!response.ok) await throwEndpointError(response, 'Token exchange');

  const data = await readJson(response, 'Token exchange');
  if (
    typeof data.access_token !== 'string' ||
    typeof data.refresh_token !== 'string'
  ) {
    throw new OpenKeyNativeError(
      'SERVER',
      'Token response missing access_token or refresh_token',
      response.status,
    );
  }

  const delegation = validateTinyCloudDelegation(
    data.tinycloud_delegation,
    {
      sessionKey: options.sessionKey,
      requestedPermissions: options.requestedPermissions,
    },
  );

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn:
      typeof data.expires_in === 'number' ? data.expires_in : undefined,
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
  /** Optional renewal narrowing + SIWE nonce (plan §1.4). */
  siweNonce?: string;
  permissionsSubset?: NativeDelegationPermission[];
  ttlSeconds?: number;
  fetchFn?: NativeFetch;
  sha256Fn?: SHA256Fn;
}

export interface RenewDelegationResult {
  refreshToken: string;
  expiresIn?: number;
  delegation: TinyCloudDelegation;
}

/**
 * Renew a delegation (plan §1.4): `POST
 * {metadata.tinycloudDelegationRenewEndpoint}` with JSON
 * `{client_id, refresh_token}` and `OpenKey-Session-Proof` where `cred_hash =
 * b64url(sha256(refresh_token))`.
 */
export async function renewDelegation(
  options: RenewDelegationOptions,
): Promise<RenewDelegationResult> {
  const fetchFn =
    options.fetchFn ?? (fetch as unknown as NativeFetch);
  const htu = options.metadata.tinycloudDelegationRenewEndpoint;

  const requestedPermissions =
    options.permissionsSubset ?? options.requestedPermissions;
  const authorizationDetails = options.permissionsSubset
    ? buildAuthorizationDetails({
        sessionKey: options.sessionKey,
        permissions: options.permissionsSubset,
        ttlSeconds: options.ttlSeconds,
        siweNonce: options.siweNonce,
      })
    : undefined;

  const proof = await signSessionProof({
    sessionKey: options.sessionKey,
    htm: 'POST',
    htu,
    clientId: options.clientId,
    credential: options.refreshToken,
    siweNonce: options.siweNonce,
    authorizationDetails,
    sha256Fn: options.sha256Fn,
  });

  const response = await postForm(
    htu,
    JSON.stringify({
      client_id: options.clientId,
      refresh_token: options.refreshToken,
    }),
    'application/json',
    fetchFn,
    { [SESSION_PROOF_HEADER]: proof },
  );
  if (!response.ok) await throwEndpointError(response, 'Renew');

  const data = await readJson(response, 'Renew');
  if (typeof data.refresh_token !== 'string') {
    throw new OpenKeyNativeError(
      'SERVER',
      'Renew response missing refresh_token',
      response.status,
    );
  }

  const delegation = validateTinyCloudDelegation(data.tinycloud_delegation, {
    sessionKey: options.sessionKey,
    requestedPermissions,
  });

  return {
    refreshToken: data.refresh_token,
    expiresIn:
      typeof data.expires_in === 'number' ? data.expires_in : undefined,
    delegation,
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
}

/**
 * Revoke a grant (plan §1.5): `POST
 * {metadata.tinycloudDelegationRevocationEndpoint}` with JSON
 * `{client_id, refresh_token}` and `OpenKey-Session-Proof` where `cred_hash =
 * b64url(sha256(refresh_token))`. Resolves on success or when the server
 * reports `invalid_grant` (already revoked — the endpoint is idempotent).
 */
export async function revokeDelegation(
  options: RevokeDelegationOptions,
): Promise<void> {
  const fetchFn =
    options.fetchFn ?? (fetch as unknown as NativeFetch);
  const htu = options.metadata.tinycloudDelegationRevocationEndpoint;
  const proof = await signSessionProof({
    sessionKey: options.sessionKey,
    htm: 'POST',
    htu,
    clientId: options.clientId,
    credential: options.refreshToken,
    sha256Fn: options.sha256Fn,
  });

  const response = await postForm(
    htu,
    JSON.stringify({
      client_id: options.clientId,
      refresh_token: options.refreshToken,
    }),
    'application/json',
    fetchFn,
    { [SESSION_PROOF_HEADER]: proof },
  );
  if (response.ok) return;

  try {
    await throwEndpointError(response, 'Revoke');
  } catch (error) {
    // Idempotent: a missing/revoked grant (server `invalid_grant`) means the
    // goal is already reached. A proof failure still propagates.
    if (
      error instanceof OpenKeyNativeError &&
      error.serverError === 'invalid_grant'
    ) {
      return;
    }
    throw error;
  }
}
