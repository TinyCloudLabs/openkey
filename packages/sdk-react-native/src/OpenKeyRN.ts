import type {
  OpenKeyRNConfig,
  OpenKeyRNAuthTokens,
  OpenKeyRNDelegationConfig,
} from './types';
import { OpenKeyError } from './types';
import type { OpenKeySecureStore } from './types';
import type {
  NativeDelegationPermission,
  NativeSessionKeypair,
  OpenKeyServerMetadata,
  RenewDelegationResult,
  SHA256Fn,
  TinyCloudDelegation,
} from '@openkey/core';
import {
  OpenKeyNativeError,
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  refreshAccessToken,
  DEFAULT_DELEGATION_SCOPES,
  generateSessionKeypair,
  sessionKeypairFromJwk,
  discoverOpenKeyServer,
  sendParRequest,
  buildNativeAuthorizeUrl,
  parseNativeCallback,
  exchangeDelegationCode,
  delegationNeedsRenewalNow,
  normalizeDelegationPermissions,
  renewDelegation,
  revokeDelegation,
} from '@openkey/core';

/**
 * The result shape of `expo-web-browser`'s `openAuthSessionAsync` (and the
 * equivalent ASWebAuthenticationSession / Custom Tab wrappers).
 */
export type BrowserResult =
  | { type: 'success'; url: string }
  // 'locked' is the expo-web-browser result when another auth session is
  // already open; it settles the sign-in as USER_CANCELLED too.
  | { type: 'cancel' | 'dismiss' | 'locked' };

/**
 * A function that opens a URL in the system browser (e.g. via expo-web-browser or react-native Linking).
 * The consumer MUST provide this — there is no default.
 *
 * Contract (v0.9+):
 * - Resolve `{ type: 'success', url }` and the SDK feeds `url` into
 *   `handleCallback()` itself.
 * - Resolve `{ type: 'cancel' }` or `{ type: 'dismiss' }` and the pending
 *   `signIn()` rejects with `USER_CANCELLED` immediately.
 * - Resolve `void` (legacy opener) and nothing changes: the SDK waits for a
 *   deep-link `handleCallback(url)` call or the timeout.
 * - Reject (or throw synchronously) and the pending `signIn()` rejects with
 *   the thrown error (`OpenKeyError`/`OpenKeyNativeError` pass through;
 *   anything else becomes `UNKNOWN`).
 *
 * `redirectUri` is passed through so the opener can hand it to
 * `openAuthSessionAsync`.
 */
export type BrowserOpener = (
  url: string,
  redirectUri: string,
) => Promise<BrowserResult | void>;

/**
 * Full configuration for OpenKeyRN, extending the base config with
 * the required browser opener and optional overrides.
 */
export interface OpenKeyRNFullConfig extends OpenKeyRNConfig {
  /** Required: function to open the authorization URL in a browser */
  openBrowser: BrowserOpener;
  /** Optional custom SHA-256 for older Hermes runtimes */
  sha256?: SHA256Fn;
  /** Timeout in ms for the sign-in flow (default: 300_000 = 5 minutes) */
  timeoutMs?: number;
}

interface PendingDelegationFlow {
  sessionKey: NativeSessionKeypair;
  metadata: OpenKeyServerMetadata;
  /** The permission list sent on PAR (un-normalized; core prepends capabilities/read). */
  permissions: NativeDelegationPermission[];
  /** sessionGeneration captured at sign-in; checked before persisting. */
  generation: number;
}

interface PendingFlow {
  state: string;
  verifier: string;
  /** Timeout handle; cleared when the flow settles through any path. */
  timer?: ReturnType<typeof setTimeout>;
  /** Present when this flow runs the TinyCloud native-delegation protocol. */
  delegation?: PendingDelegationFlow;
  resolve: (tokens: OpenKeyRNAuthTokens) => void;
  reject: (error: Error) => void;
}

interface DelegationSession {
  sessionKey: NativeSessionKeypair;
  refreshToken: string;
  /**
   * The approved set from the code exchange; basis for renew subset checks.
   * A `permissionsSubset` renew never narrows it.
   */
  permissions: NativeDelegationPermission[];
  /** Absolute grant expiry (ms): `renewableUntil` + 300 s, when known. */
  grantExpiresAt?: number;
  /**
   * When `refreshToken` expires (ms): 7 days after it was issued, capped
   * by `grantExpiresAt`. Absent on records written before it was tracked.
   */
  refreshTokenExpiresAt?: number;
}

/** JSON shape persisted through `OpenKeySecureStore`. */
interface StoredDelegationSession {
  privateJwk: NativeSessionKeypair['privateJwk'];
  refreshToken: string;
  permissions: NativeDelegationPermission[];
  grantExpiresAt?: number;
  refreshTokenExpiresAt?: number;
}

/**
 * A grant whose revoke failed transiently at signOut(). Holds what the
 * revoke needs plus its retry bounds; it is retried on signOut(), on
 * construction and on signIn(), and dropped once the revoke succeeds or
 * fails terminally, once `expiresAt` has passed, or after
 * `MAX_REVOKE_ATTEMPTS` attempts.
 */
interface StoredPendingRevoke {
  privateJwk: NativeSessionKeypair['privateJwk'];
  refreshToken: string;
  /** Revoke attempts made so far (the failed signOut() counts as 1). */
  attempts: number;
  /** Refresh-token expiry (ms); the revoke is pointless after it. */
  expiresAt: number;
}

/**
 * Which stored session a write expects to be current. `any`: a sign-in's
 * save, which replaces whatever is stored. Otherwise the session id (the
 * session public key `x`, unique per sign-in), optionally pinned to one
 * refresh token.
 */
type SessionExpectation = 'any' | { sid: string; refreshToken?: string };

/**
 * A grant the SDK lets go of without storing it: abandonGrant() revokes it,
 * or records it as a pending revoke when the revoke fails transiently.
 *
 * Rule: an error carries `rotatedRefreshToken` only while that token is
 * live and not abandoned. Every path that hands a token to abandonGrant()
 * removes it from the error it reports.
 */
type AbandonedGrant = Pick<
  DelegationSession,
  'sessionKey' | 'refreshToken' | 'refreshTokenExpiresAt'
>;

/** Session id: the session public key's `x`, fresh for every sign-in. */
function sessionId(sessionKey: NativeSessionKeypair): string {
  return sessionKey.publicJwk.x;
}

/**
 * Storage queues, shared by every OpenKeyRN instance that uses the same
 * store object: reads and compare-and-sets from separate instances over
 * one store never interleave.
 */
const storageQueues = new WeakMap<OpenKeySecureStore, { tail: Promise<unknown> }>();

/** What a read-decide-write step on one storage key does with its value. */
interface RecordUpdate<T> {
  result: T;
  /** Present to write: the next value, or `null` to remove the key. */
  write?: { value: string | null };
}

/** Spec: every refresh token lives 7 days. */
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** Spec: `renewableUntil` is `absoluteExpiresAt − 300 s`. */
const RENEWABLE_UNTIL_LEAD_MS = 300_000;
/** A pending revoke is dropped after this many attempts. */
const MAX_REVOKE_ATTEMPTS = 20;

/**
 * Absolute grant expiry (ms) from a delegation's `renewableUntil` (ISO
 * string or epoch seconds/ms, as core accepts), or `undefined` when absent
 * or unparseable.
 */
function grantExpiresAt(delegation: TinyCloudDelegation): number | undefined {
  const value = delegation.renewableUntil;
  let ms: number;
  if (typeof value === 'number') {
    ms = value > 1e11 ? value : value * 1000;
  } else if (typeof value === 'string') {
    ms = Date.parse(value);
  } else {
    return undefined;
  }
  return Number.isFinite(ms) && ms > 0
    ? ms + RENEWABLE_UNTIL_LEAD_MS
    : undefined;
}

/** `session` holding a freshly issued `refreshToken` (7-day TTL). */
function withRefreshToken(
  session: DelegationSession,
  refreshToken: string,
): DelegationSession {
  const ttlEnd = Date.now() + REFRESH_TOKEN_TTL_MS;
  return {
    ...session,
    refreshToken,
    refreshTokenExpiresAt:
      session.grantExpiresAt === undefined
        ? ttlEnd
        : Math.min(ttlEnd, session.grantExpiresAt),
  };
}

/** Spec issuer: the OpenKey authorization server, not the app host. */
const DEFAULT_ISSUER = 'https://api.openkey.so/api/auth';

const CALLBACK_PARAMS = ['code', 'error', 'state', 'iss'] as const;

/** Native codes that exist on OpenKeyErrorCode verbatim (plain mode). */
const PLAIN_CALLBACK_CODES = new Set([
  'USER_CANCELLED',
  'ACCESS_DENIED',
  'STATE_MISMATCH',
  'SERVER',
]);

/**
 * Renew/exchange errors that mean the server-side grant is already dead:
 * the local session must be wiped before the error is rethrown (spec:
 * "terminal from renew means a local sign-out").
 */
const TERMINAL_SESSION_CODES = new Set([
  'INVALID_GRANT',
  'CONSENT_REQUIRED',
  'ACCESS_DENIED',
  'SPACE_UNAVAILABLE',
]);

/**
 * Revoke errors that a retry can fix: the grant may still be active, so
 * signOut keeps a pending revoke and rejects. Besides these codes, any
 * HTTP 5xx on the revoke path (revoke endpoint or server discovery) and
 * HTTP 429 are transient — a server outage or rate limit must not wipe
 * credentials. Every other revoke error (INVALID_GRANT, CONSENT_REQUIRED,
 * ACCESS_DENIED, SPACE_UNAVAILABLE, any other 4xx, …) is terminal:
 * retrying won't change it, so signOut wipes and resolves.
 */
const TRANSIENT_REVOKE_CODES = new Set(['NETWORK', 'TEMPORARILY_UNAVAILABLE']);

function isTransientRevokeError(error: unknown): error is OpenKeyNativeError {
  return (
    error instanceof OpenKeyNativeError &&
    (TRANSIENT_REVOKE_CODES.has(error.code) ||
      (error.status !== undefined &&
        (error.status >= 500 || error.status === 429)))
  );
}

/**
 * Extract the OAuth response parameters from a callback URL: query first,
 * fragment as fallback. Returns `null` for URLs carrying none of them.
 */
function extractCallbackParams(url: string): URLSearchParams | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const hasAuthParams = (params: URLSearchParams) =>
    CALLBACK_PARAMS.some((key) => params.has(key));
  if (hasAuthParams(parsed.searchParams)) return parsed.searchParams;
  if (parsed.hash.length > 1) {
    const fragment = new URLSearchParams(
      parsed.hash.startsWith('#') ? parsed.hash.slice(1) : parsed.hash,
    );
    if (hasAuthParams(fragment)) return fragment;
  }
  return null;
}

/** The stored session record for `raw`: `null` if absent, `'corrupt'` if unparseable. */
function parseStoredSession(raw: string | null): DelegationSession | null | 'corrupt' {
  if (!raw) return null;
  try {
    const record = JSON.parse(raw) as StoredDelegationSession;
    return {
      sessionKey: sessionKeypairFromJwk(record.privateJwk),
      refreshToken: record.refreshToken,
      permissions: record.permissions,
      grantExpiresAt: record.grantExpiresAt,
      refreshTokenExpiresAt: record.refreshTokenExpiresAt,
    };
  } catch {
    return 'corrupt';
  }
}

function serializeSession(session: DelegationSession): string {
  const record: StoredDelegationSession = {
    privateJwk: session.sessionKey.privateJwk,
    refreshToken: session.refreshToken,
    permissions: session.permissions,
    grantExpiresAt: session.grantExpiresAt,
    refreshTokenExpiresAt: session.refreshTokenExpiresAt,
  };
  return JSON.stringify(record);
}

/** The pending-revoke entries in `raw` (`[]` if absent), or `null` if corrupt. */
function parsePendingRevokes(raw: string | null): StoredPendingRevoke[] | null {
  if (!raw) return [];
  try {
    const entries = JSON.parse(raw) as StoredPendingRevoke[];
    if (!Array.isArray(entries)) return null;
    for (const entry of entries) {
      sessionKeypairFromJwk(entry.privateJwk);
      if (
        typeof entry.refreshToken !== 'string' ||
        !Number.isInteger(entry.attempts) ||
        !Number.isFinite(entry.expiresAt)
      ) {
        return null;
      }
    }
    return entries;
  } catch {
    return null;
  }
}

/**
 * Identity for a renew() call's options — concurrent renew()s with the
 * same key share the in-flight promise; different keys queue behind it.
 * The subset is keyed on its normalized (wire) form, so a subset with and
 * without the prepended `tinycloud.capabilities/read` share one renewal.
 */
function renewKey(options?: {
  permissionsSubset?: NativeDelegationPermission[];
  siweNonce?: string;
}): string {
  const subset = options?.permissionsSubset
    ? JSON.stringify(
        normalizeDelegationPermissions(options.permissionsSubset).map((p) => [
          p.service,
          p.space,
          p.path ?? '',
          p.actions,
        ]),
      )
    : '';
  return `${options?.siweNonce ?? ''}#${subset}`;
}

/**
 * OAuth 2.0 PKCE client for React Native.
 *
 * Usage:
 * 1. Create an instance with your config and a browser opener function.
 * 2. Call `signIn()` — this opens the browser and returns a Promise<OpenKeyRNAuthTokens>.
 * 3. When the opener reports `{type: 'success', url}` (or your app receives
 *    the redirect via deep link), the SDK completes the flow; legacy openers
 *    rely on `handleCallback(url)`.
 * 4. The signIn() promise resolves with the tokens.
 *
 * With `config.delegation`, sign-in additionally runs the TinyCloud
 * native-delegation protocol (PAR + Ed25519 session key + session proofs from
 * `@openkey/core`), resolves with `tokens.delegation` set, and enables
 * `renew()` for the lifetime of the grant.
 */
export class OpenKeyRN {
  private host: string;
  private clientId: string;
  private redirectUri: string;
  private issuer: string;
  private scopes: string[];
  private resource?: string;
  private delegation?: OpenKeyRNDelegationConfig;
  /** Storage key for the persisted delegation session record. */
  private delegationStorageKey: string;
  /** Storage key for grants whose revoke failed transiently (JSON array). */
  private pendingRevokeStorageKey: string;
  private openBrowser: BrowserOpener;
  private sha256?: SHA256Fn;
  private timeoutMs: number;

  private pendingFlows: Map<string, PendingFlow> = new Map();
  private metadataPromise?: Promise<OpenKeyServerMetadata>;
  private renewInFlight?: Promise<RenewDelegationResult>;
  /**
   * Bumped by signOut(). signIn() and renew() capture it when they start
   * and check it before every write.
   */
  private sessionGeneration = 0;
  /** Options of the in-flight renew; queued callers compare against it. */
  private renewInFlightKey?: string;
  /** signOut()s in progress: while any runs, the user reads as signed out. */
  private signOutFlights = new Set<Promise<unknown>>();
  /** Single-flight retry of the pending-revoke record. */
  private pendingRevokeRetry?: Promise<Error | undefined>;

  constructor(config: OpenKeyRNFullConfig) {
    this.host = config.host;
    this.clientId = config.clientId;
    this.redirectUri = config.redirectUri;
    this.issuer = config.issuer ?? DEFAULT_ISSUER;
    this.scopes = config.scopes ?? [
      'openid',
      'email',
      'keys',
      'offline_access',
    ];
    this.resource = config.resource;
    if (
      config.delegation &&
      typeof config.delegation.verifyDelegation !== 'function'
    ) {
      // Fail closed: delegation mode without signature verification would
      // trust an unverified server payload (spec: the SDK verifies siwe +
      // signature reproduce delegationHeader/delegationCid).
      throw new OpenKeyNativeError(
        'UNAVAILABLE',
        'delegation.verifyDelegation is required',
      );
    }
    this.delegation = config.delegation;
    this.delegationStorageKey = `openkey:tinycloud-delegation:${this.clientId}`;
    this.pendingRevokeStorageKey = `openkey:tinycloud-delegation-pending-revoke:${this.clientId}`;
    this.openBrowser = config.openBrowser;
    this.sha256 = config.sha256;
    this.timeoutMs = config.timeoutMs ?? 300_000;

    // Retry grants a previous signOut() could not revoke. Best-effort: a
    // grant that still fails stays recorded for the next attempt.
    if (this.delegation) void this.retryPendingRevokes().catch(() => {});
  }

  /**
   * Initiate the OAuth 2.0 Authorization Code + PKCE sign-in flow.
   *
   * Opens the authorization URL in the browser. The returned promise
   * resolves when the opener returns `{type: 'success', url}` or
   * `handleCallback()` is called with the matching redirect URL, rejects
   * with `USER_CANCELLED` on `{type: 'cancel' | 'dismiss'}` (or an
   * `error=access_denied` callback, which surfaces as `ACCESS_DENIED`),
   * with `STATE_MISMATCH` on a callback `state`/`iss` mismatch, and with
   * `TIMEOUT` after `timeoutMs`.
   */
  async signIn(): Promise<OpenKeyRNAuthTokens> {
    // Taken before the first await: a signOut() that completes during
    // discovery or PAR invalidates this sign-in.
    const generation = this.sessionGeneration;
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier, this.sha256);
    const state = generateState();

    let authUrl: string;
    let delegationFlow: PendingDelegationFlow | undefined;

    if (this.delegation) {
      // Best-effort, like on construction; never blocks the sign-in.
      void this.retryPendingRevokes().catch(() => {});
      const cfg = this.delegation;
      const sessionKey = generateSessionKeypair();
      const metadata = await this.ensureMetadata();
      const par = await sendParRequest(
        metadata,
        {
          clientId: this.clientId,
          redirectUri: this.redirectUri,
          state,
          codeChallenge: challenge,
          sessionKey,
          permissions: cfg.permissions,
          ttlSeconds: cfg.ttlSeconds,
          siweNonce: cfg.siweNonce,
          extraScopes: this.scopes.filter(
            (scope) => !DEFAULT_DELEGATION_SCOPES.includes(scope),
          ),
        },
        cfg.fetchFn,
      );
      if (generation !== this.sessionGeneration) {
        throw new OpenKeyNativeError(
          'NOT_SIGNED_IN',
          'sign-out during sign-in; sign-in discarded',
        );
      }
      authUrl = buildNativeAuthorizeUrl({
        authorizationEndpoint: metadata.authorizationEndpoint,
        clientId: this.clientId,
        requestUri: par.requestUri,
      });
      delegationFlow = {
        sessionKey,
        metadata,
        permissions: cfg.permissions,
        generation,
      };
    } else {
      authUrl = buildAuthorizationUrl({
        host: this.host,
        clientId: this.clientId,
        redirectUri: this.redirectUri,
        codeChallenge: challenge,
        state,
        scopes: this.scopes,
      });
    }

    const tokensPromise = this.registerPendingFlow(state, verifier, delegationFlow);

    try {
      const result = await this.openBrowser(authUrl, this.redirectUri);
      this.settleFromOpenerResult(state, result);
    } catch (error) {
      this.removePending(state)?.reject(this.normalizeError(error));
    }

    return tokensPromise;
  }

  /**
   * Handle an incoming redirect callback URL.
   *
   * Call this when your app receives a deep link / URL callback from the browser.
   * Returns `true` if the URL was recognized and handled, `false` otherwise.
   *
   * The token exchange happens asynchronously — the pending `signIn()`
   * promise resolves or rejects based on the exchange result. A callback
   * for a pending flow whose `iss` mismatches rejects it with
   * `STATE_MISMATCH`; `error=access_denied` rejects it with
   * `ACCESS_DENIED` and any other `error` with `SERVER`. A callback whose
   * `state` matches no pending flow is ignored and returns `false` — a
   * `STATE_MISMATCH` on `state` can only surface through the flow's own
   * opener result.
   */
  handleCallback(url: string): boolean {
    const params = extractCallbackParams(url);
    if (!params) return false;

    // A callback whose state matches no pending flow is not ours: ignore it.
    const state = params.get('state');
    const pending = state ? this.pendingFlows.get(state) : undefined;
    if (!pending) return false;

    // Remove from pending immediately to prevent double-handling.
    this.removePending(pending.state);

    void this.settleFlowFromCallback(pending, url);
    return true;
  }

  /**
   * Refresh an access token using a refresh token (plain mode only).
   * Delegation clients can't use the provider refresh grant — use `renew()`.
   */
  async refreshToken(refreshTokenValue: string): Promise<OpenKeyRNAuthTokens> {
    if (this.delegation) {
      throw new OpenKeyNativeError(
        'UNAVAILABLE',
        'refreshToken() is unavailable in delegation mode; use renew()',
      );
    }
    return refreshAccessToken({
      host: this.host,
      refreshToken: refreshTokenValue,
      clientId: this.clientId,
      resource: this.resource,
    });
  }

  /**
   * Renew the TinyCloud delegation (delegation mode only).
   *
   * Single-flight, keyed on options: concurrent calls with equivalent
   * `permissionsSubset` (compared in normalized form) and the same
   * `siweNonce` share one renewal; a call with different options is queued
   * behind the in-flight one, so two renewals never race the same refresh
   * token. `permissionsSubset` shapes only this delegation: the stored
   * approved set is never narrowed, so a later plain renew asks for the
   * full approved set again. Persists the rotated refresh token before
   * resolving; on `RENEWAL_CONFLICT` reloads the stored token and retries
   * once. Terminal errors (`INVALID_GRANT`, `CONSENT_REQUIRED`,
   * `ACCESS_DENIED`, `SPACE_UNAVAILABLE`) wipe the local session before
   * rethrowing (spec: a terminal renew error is a local sign-out); a
   * rotated token on a terminal error is not persisted, its grant is
   * abandoned (revoked, or a pending revoke). On a non-terminal error the
   * rotated token is persisted first. An error carries
   * `rotatedRefreshToken` only while that token is live and not abandoned:
   * after a terminal outcome, a refused save or a failed secure-store
   * write, the grant is abandoned and the error carries no token.
   * A `signOut()` during renewal makes it discard the result and reject
   * `NOT_SIGNED_IN` instead of persisting over the wiped session.
   */
  async renew(options?: {
    permissionsSubset?: NativeDelegationPermission[];
    siweNonce?: string;
  }): Promise<RenewDelegationResult> {
    if (this.delegation === undefined) {
      throw new OpenKeyNativeError(
        'UNAVAILABLE',
        'renew() requires config.delegation',
      );
    }
    const key = renewKey(options);
    if (
      this.renewInFlight !== undefined &&
      this.renewInFlightKey === key
    ) {
      return this.renewInFlight;
    }
    // Different options (or none in flight): chain behind the current
    // renew so the same refresh token is never raced concurrently.
    const run = (this.renewInFlight ?? Promise.resolve())
        .catch(() => {})
        .then(() => this.renewOnce(options, this.sessionGeneration));
    this.renewInFlight = run;
    this.renewInFlightKey = key;
    try {
      return await run;
    } finally {
      if (this.renewInFlight === run) {
        this.renewInFlight = undefined;
        this.renewInFlightKey = undefined;
      }
    }
  }

  /**
   * Sign out: revoke the delegation grant (delegation mode), clear pending
   * sign-in flows, and — when `accessToken` is given — revoke it through
   * the legacy `/api/auth/revoke` endpoint.
   *
   * The user reads as signed out from the moment signOut() starts:
   * `renew()` rejects `NOT_SIGNED_IN`. A TRANSIENT revoke failure
   * (`NETWORK`, `TEMPORARILY_UNAVAILABLE` still failing after the internal
   * retry, or any HTTP 5xx from the revoke endpoint or server discovery)
   * leaves the grant possibly active: the session record
   * is replaced by a pending-revoke record holding only the session key
   * and refresh token, and signOut rejects with the typed error. Every
   * other revoke failure is terminal — a retry won't change it — so the
   * session is wiped and signOut resolves. Pending revokes are retried on
   * the next signOut(), on construction and on signIn(), and dropped once
   * they succeed or fail terminally.
   *
   * signOut() signs out whatever session is current: the final remove is a
   * compare-and-set on the session it revoked, and if a different session
   * was stored meanwhile (only possible from another instance sharing the
   * storage — this instance's sign-ins wait for signOut() before saving)
   * that one is revoked and removed too. A storage failure rejects with a
   * typed `STORAGE` error; a record that can't be read is never removed,
   * and signOut() then never reports success.
   */
  async signOut(accessToken?: string): Promise<void> {
    // Clear all pending flows (removePending clears their timers too).
    for (const state of [...this.pendingFlows.keys()]) {
      this.removePending(state)?.reject(
        new OpenKeyError('USER_CANCELLED', 'Sign-out cancelled pending sign-in'),
      );
    }

    // Invalidate any in-flight renew/exchange persistence: those calls
    // discard their result and reject NOT_SIGNED_IN instead of writing a
    // session record past this point.
    this.sessionGeneration += 1;

    let firstError: unknown;
    if (this.delegation) {
      const flight = this.signOutDelegation();
      this.signOutFlights.add(flight);
      try {
        firstError = await flight;
      } finally {
        this.signOutFlights.delete(flight);
      }
    }

    if (accessToken !== undefined) {
      try {
        const response = await fetch(`${this.host}/api/auth/revoke`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({ token: accessToken }).toString(),
        });

        if (!response.ok) {
          let detail = '';
          try {
            detail = await response.text();
          } catch {
            // ignore
          }
          throw new OpenKeyError(
            'NETWORK_ERROR',
            `Revocation failed: ${response.status} ${response.statusText}${detail ? ` - ${detail}` : ''}`,
          );
        }
      } catch (error) {
        if (firstError === undefined) {
          firstError =
            error instanceof OpenKeyError
              ? error
              : new OpenKeyError(
                  'NETWORK_ERROR',
                  error instanceof Error ? error.message : 'Network request failed',
                );
        }
      }
    }

    if (firstError !== undefined) throw firstError;
  }

  // ======= Internals =======

  /**
   * Delegation half of signOut(). Returns the error signOut() rejects with
   * — any failure to read or save local state first (`STORAGE`), then the
   * typed revoke error — or `undefined`.
   */
  private async signOutDelegation(): Promise<unknown> {
    // Grants left by an earlier signOut() go first. A failure to save
    // local state outranks a revoke error: it is reported as STORAGE.
    let pendingError: unknown;
    let storageFailure: OpenKeyNativeError | undefined;
    try {
      pendingError = await this.retryPendingRevokes();
    } catch (error) {
      storageFailure =
        error instanceof OpenKeyNativeError && error.code === 'STORAGE'
          ? error
          : this.storageError('update pending revokes', error);
    }

    let revokeError: Error | undefined;
    for (;;) {
      let session: DelegationSession | null;
      try {
        session = await this.runInStorageQueue(() => this.readStoredSession());
      } catch (error) {
        // Unreadable: nothing is removed, and the caller is not told the
        // sign-out succeeded.
        return this.storageError('read stored delegation session', error);
      }
      if (!session) break;

      const error = await this.revokeGrant(
        session.sessionKey,
        session.refreshToken,
      );
      revokeError ??= error;
      try {
        // The credentials reach the pending-revoke record before the
        // session record can be removed: a failed write never loses the
        // token needed to retry the revoke.
        if (error) await this.appendPendingRevoke(session);
        await this.commitSession(null, {
          sid: sessionId(session.sessionKey),
          refreshToken: session.refreshToken,
        });
        break;
      } catch (caught) {
        if (
          caught instanceof OpenKeyNativeError &&
          caught.code === 'NOT_SIGNED_IN'
        ) {
          // The record changed while this one was revoked: sign out
          // whatever is current now (or stop if nothing is).
          continue;
        }
        // Local state could not be saved — the pending revoke, or the
        // removal of the session — so this is STORAGE, with the revoke
        // error (if any) as its cause.
        return this.storageError(
          error
            ? 'record the pending revoke or remove the stored delegation session'
            : 'remove stored delegation session',
          caught,
          revokeError,
        );
      }
    }
    return storageFailure ?? revokeError ?? pendingError;
  }

  /** Add a pending-revoke entry for `grant`. */
  private appendPendingRevoke(grant: AbandonedGrant): Promise<void> {
    return this.runInStorageQueue(() =>
      this.updateRecord(this.pendingRevokeStorageKey, (raw) => {
        const entries = parsePendingRevokes(raw) ?? [];
        if (entries.some((entry) => entry.refreshToken === grant.refreshToken)) {
          return { result: undefined };
        }
        entries.push({
          privateJwk: grant.sessionKey.privateJwk,
          refreshToken: grant.refreshToken,
          attempts: 1,
          // A record from before expiry tracking: the token was issued
          // before now, so now + 7 days is an upper bound.
          expiresAt:
            grant.refreshTokenExpiresAt ?? Date.now() + REFRESH_TOKEN_TTL_MS,
        });
        return { result: undefined, write: { value: JSON.stringify(entries) } };
      }),
    );
  }

  /**
   * Revoke one grant. Resolves the typed error on a transient failure
   * (`isTransientRevokeError`), when a retry may still revoke it; resolves
   * `undefined` on success or any terminal failure.
   */
  private async revokeGrant(
    sessionKey: NativeSessionKeypair,
    refreshToken: string,
  ): Promise<Error | undefined> {
    const cfg = this.delegation!;
    try {
      await revokeDelegation({
        metadata: await this.ensureMetadata(),
        clientId: this.clientId,
        refreshToken,
        sessionKey,
        fetchFn: cfg.fetchFn,
        sha256Fn: this.sha256,
        sleepFn: cfg.sleepFn,
      });
      return undefined;
    } catch (error) {
      return isTransientRevokeError(error) ? error : undefined;
    }
  }

  /**
   * Let go of a grant the SDK will not store — the session a sign-in
   * replaced, a superseded renew's or sign-in's token, a terminal
   * outcome's rotated token. It is revoked; when the revoke fails
   * transiently it becomes a pending revoke (same bounded entry as
   * signOut()), retried later. Never throws: the callers are already
   * reporting their own outcome.
   */
  private async abandonGrant(grant: AbandonedGrant): Promise<void> {
    const error = await this.revokeGrant(grant.sessionKey, grant.refreshToken);
    if (error) await this.appendPendingRevoke(grant).catch(() => {});
  }

  /**
   * Retry every pending revoke (single-flight). Entries that are revoked,
   * fail terminally, are past their refresh-token expiry or reach
   * `MAX_REVOKE_ATTEMPTS` are dropped; the rest stay with their attempt
   * count bumped. Resolves the first
   * transient revoke error, or `undefined`. Rejects with `STORAGE` on a
   * storage failure, with that transient revoke error (if any) as `cause`.
   */
  private retryPendingRevokes(): Promise<Error | undefined> {
    if (!this.pendingRevokeRetry) {
      const run = this.retryPendingRevokesOnce();
      this.pendingRevokeRetry = run;
      void run
        .finally(() => {
          if (this.pendingRevokeRetry === run) {
            this.pendingRevokeRetry = undefined;
          }
        })
        .catch(() => {});
    }
    return this.pendingRevokeRetry;
  }

  private async retryPendingRevokesOnce(): Promise<Error | undefined> {
    let entries: StoredPendingRevoke[];
    try {
      entries = await this.runInStorageQueue(() => this.readPendingRevokes());
    } catch (error) {
      throw this.storageError('read pending revokes', error);
    }
    if (entries.length === 0) return undefined;

    let firstError: Error | undefined;
    // Entries to drop, and new attempt counts for the ones kept.
    const done = new Set<string>();
    const attempts = new Map<string, number>();
    for (const entry of entries) {
      if (
        Date.now() >= entry.expiresAt ||
        entry.attempts >= MAX_REVOKE_ATTEMPTS
      ) {
        // The token is dead, or retrying has run its course.
        done.add(entry.refreshToken);
        continue;
      }
      const error = await this.revokeGrant(
        sessionKeypairFromJwk(entry.privateJwk),
        entry.refreshToken,
      );
      if (!error) {
        done.add(entry.refreshToken);
        continue;
      }
      firstError ??= error;
      if (entry.attempts + 1 >= MAX_REVOKE_ATTEMPTS) {
        done.add(entry.refreshToken);
      } else {
        attempts.set(entry.refreshToken, entry.attempts + 1);
      }
    }

    // Re-read: a signOut() may have added an entry meanwhile.
    try {
      await this.runInStorageQueue(() =>
        this.updateRecord(this.pendingRevokeStorageKey, (raw) => {
          const remaining = (parsePendingRevokes(raw) ?? [])
            .filter((entry) => !done.has(entry.refreshToken))
            .map((entry) => ({
              ...entry,
              attempts: attempts.get(entry.refreshToken) ?? entry.attempts,
            }));
          return {
            result: undefined,
            write: {
              value: remaining.length > 0 ? JSON.stringify(remaining) : null,
            },
          };
        }),
      );
    } catch (error) {
      // The revoke error this retry already hit stays visible as the cause.
      throw this.storageError('update pending revokes', error, firstError);
    }
    return firstError;
  }

  /**
   * Read the pending-revoke record. Call inside the storage queue. A corrupt
   * record can never be revoked, so it is removed and reads as empty.
   */
  private readPendingRevokes(): Promise<StoredPendingRevoke[]> {
    return this.updateRecord(this.pendingRevokeStorageKey, (raw) => {
      const entries = parsePendingRevokes(raw);
      return entries
        ? { result: entries }
        : { result: [], write: { value: null } };
    });
  }

  /**
   * A secure-store read or write failure (`STORAGE`, never `NETWORK`).
   * `cause` is the error the operation was already reporting, if any.
   */
  private storageError(
    action: string,
    error: unknown,
    cause?: unknown,
  ): OpenKeyNativeError {
    const storage = new OpenKeyNativeError(
      'STORAGE',
      `failed to ${action}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    if (cause !== undefined) storage.cause = cause;
    return storage;
  }

  /**
   * The error to report after a rotated-token recovery save failed. The
   * save abandoned the token either way, so it leaves `original`. A
   * storage failure (`STORAGE`) is reported in place of `original`, which
   * becomes its `cause`: local state could not be saved. A refusal
   * (`NOT_SIGNED_IN`) leaves `original` as the error to report.
   */
  private afterFailedRecovery(
    original: OpenKeyNativeError,
    saveError: unknown,
  ): OpenKeyNativeError {
    original.rotatedRefreshToken = undefined;
    if (saveError instanceof OpenKeyNativeError && saveError.code === 'STORAGE') {
      saveError.cause = original;
      return saveError;
    }
    return original;
  }

  private registerPendingFlow(
    state: string,
    verifier: string,
    delegation?: PendingDelegationFlow,
  ): Promise<OpenKeyRNAuthTokens> {
    return new Promise<OpenKeyRNAuthTokens>((resolve, reject) => {
      const pending: PendingFlow = {
        state,
        verifier,
        delegation,
        resolve,
        reject,
      };
      this.pendingFlows.set(state, pending);

      // Set timeout to reject if callback never arrives
      pending.timer = setTimeout(() => {
        if (this.pendingFlows.delete(state)) {
          reject(new OpenKeyError('TIMEOUT', `Sign-in timed out after ${this.timeoutMs}ms`));
        }
      }, this.timeoutMs);

      // Ensure the timer doesn't keep the Node/Bun process alive.
      // In Node/Bun, setTimeout returns an object with unref(); in browsers it returns a number.
      const t: unknown = pending.timer;
      if (
        typeof t === 'object' &&
        t !== null &&
        'unref' in t &&
        typeof t.unref === 'function'
      ) {
        t.unref();
      }
    });
  }

  /**
   * Remove a pending flow and clear its timeout. Returns the flow so the
   * caller can settle it; `undefined` when the state isn't pending.
   */
  private removePending(state: string): PendingFlow | undefined {
    const pending = this.pendingFlows.get(state);
    if (!pending) return undefined;
    this.pendingFlows.delete(state);
    clearTimeout(pending.timer);
    return pending;
  }

  /**
   * Settle a pending flow from the opener's return value.
   * `void` (legacy opener) leaves the flow to the deep-link path / timeout.
   */
  private settleFromOpenerResult(
    state: string,
    result: BrowserResult | void,
  ): void {
    if (!result) return;
    const pending = this.removePending(state);
    if (!pending) return;
    if (result.type === 'success' && result.url) {
      // The URL came from THIS flow's opener: settle it directly. A wrong
      // state or iss inside it rejects this flow — never another flow's.
      void this.settleFlowFromCallback(pending, result.url);
      return;
    }
    // Any non-success, defined result ('cancel', 'dismiss', 'locked', …)
    // means the auth session produced no callback: settle immediately.
    pending.reject(
      new OpenKeyError(
        'USER_CANCELLED',
        `Sign-in was cancelled (browser result: ${result.type})`,
      ),
    );
  }

  /**
   * Parse the callback (iss, state, error) and run the token exchange.
   * Rejects the pending flow on any failure — never throws itself.
   */
  private async settleFlowFromCallback(
    pending: PendingFlow,
    url: string,
  ): Promise<void> {
    // True once this attempt's session has replaced the stored one. Before
    // that, a failure belongs to this attempt alone and must leave an
    // existing stored session untouched.
    let replacedStoredSession = false;
    // The approved set once the exchange returns it; the requested set
    // before that.
    let approvedPermissions = pending.delegation?.permissions ?? [];
    try {
      const callback = parseNativeCallback({
        url,
        expectedState: pending.state,
        issuer: this.issuer,
      });

      if (pending.delegation) {
        const cfg = this.delegation!;
        const flow = pending.delegation;
        const generation = flow.generation;
        const result = await exchangeDelegationCode({
          metadata: flow.metadata,
          code: callback.code,
          redirectUri: this.redirectUri,
          clientId: this.clientId,
          codeVerifier: pending.verifier,
          sessionKey: flow.sessionKey,
          requestedPermissions: flow.permissions,
          expectedTinycloudHost: cfg.tinycloudHost,
          fetchFn: cfg.fetchFn,
          sha256Fn: this.sha256,
        });
        approvedPermissions = result.delegation.permissions;

        // The SDK verifies the delegation itself: siwe + signature must
        // reproduce delegationHeader/delegationCid (spec). If this fails the
        // code was still exchanged, so surface the refresh token on the
        // error — the caller must persist it or the session is lost.
        await this.verifyDelegationOrThrow(
          result.delegation,
          result.refreshToken,
        );

        let session = withRefreshToken(
          {
            sessionKey: flow.sessionKey,
            refreshToken: result.refreshToken,
            permissions: approvedPermissions,
            grantExpiresAt: grantExpiresAt(result.delegation),
          },
          result.refreshToken,
        );
        // Persist BEFORE any immediate renew so the live refresh token is
        // never lost (spec). A signOut() during the exchange invalidates
        // this write; the orphaned grant is revoked best-effort.
        await this.saveSession(session, 'any', generation);
        replacedStoredSession = true;

        let delegation = result.delegation;
        // Renew immediately when the returned delegation is already inside
        // the renewal lead window, so signIn never resolves with an
        // almost-expired delegation (spec renewal schedule). On a
        // non-terminal failure the error is surfaced (with
        // rotatedRefreshToken when the server had already rotated) and the
        // initial session stays persisted.
        if (delegationNeedsRenewalNow(delegation)) {
          const renewed = await renewDelegation({
            metadata: flow.metadata,
            clientId: this.clientId,
            refreshToken: session.refreshToken,
            sessionKey: flow.sessionKey,
            requestedPermissions: approvedPermissions,
            expectedTinycloudHost: cfg.tinycloudHost,
            fetchFn: cfg.fetchFn,
            sha256Fn: this.sha256,
            sleepFn: cfg.sleepFn,
          });
          await this.verifyDelegationOrThrow(
            renewed.delegation,
            renewed.refreshToken,
          );
          session = withRefreshToken(session, renewed.refreshToken);
          await this.saveSession(
            session,
            { sid: sessionId(flow.sessionKey) },
            generation,
          );
          delegation = renewed.delegation;
        }

        pending.resolve({
          accessToken: result.accessToken,
          // The native flow issues no ID token; keep the AuthTokens shape.
          idToken: '',
          refreshToken: session.refreshToken,
          expiresIn: result.expiresIn ?? 0,
          delegation,
        });
        return;
      }

      const tokens = await exchangeAuthorizationCode({
        host: this.host,
        code: callback.code,
        redirectUri: this.redirectUri,
        clientId: this.clientId,
        codeVerifier: pending.verifier,
        resource: this.resource,
      });
      pending.resolve(tokens);
    } catch (error) {
      if (pending.delegation && error instanceof OpenKeyNativeError) {
        pending.reject(
          await this.settleFailedDelegationSignIn(
            error,
            pending.delegation,
            replacedStoredSession,
            approvedPermissions,
          ),
        );
        return;
      }
      pending.reject(
        pending.delegation
          ? this.normalizeError(error)
          : this.toPlainError(error),
      );
    }
  }

  /**
   * Local state after a delegation sign-in fails.
   *
   * - `NOT_SIGNED_IN`: a signOut() or a newer session won; saveSession
   *   already discarded the session and abandoned its grant.
   * - Terminal (`TERMINAL_SESSION_CODES`): the outcome is final, so nothing
   *   is persisted. The session this attempt stored (if any) is wiped, and
   *   a rotated grant is abandoned (revoked, or a pending revoke) and its
   *   token removed from the error. A stored session from before
   *   this attempt is left alone.
   * - Otherwise, a rotated refresh token is live and the old one dead, so
   *   it is persisted before the error is reported (spec). When that save
   *   fails the grant is abandoned and the token removed from the error;
   *   a storage failure is reported as `STORAGE` with the original error
   *   as its `cause`.
   *
   * Resolves the error to reject sign-in with.
   */
  private async settleFailedDelegationSignIn(
    error: OpenKeyNativeError,
    flow: PendingDelegationFlow,
    replacedStoredSession: boolean,
    approvedPermissions: NativeDelegationPermission[],
  ): Promise<OpenKeyNativeError> {
    if (error.code === 'NOT_SIGNED_IN') return error;
    if (TERMINAL_SESSION_CODES.has(error.code)) {
      if (replacedStoredSession) await this.removeSession(flow.sessionKey);
      if (error.rotatedRefreshToken) {
        await this.abandonGrant(
          withRefreshToken(
            {
              sessionKey: flow.sessionKey,
              refreshToken: error.rotatedRefreshToken,
              permissions: approvedPermissions,
            },
            error.rotatedRefreshToken,
          ),
        );
        error.rotatedRefreshToken = undefined;
      }
      return error;
    }
    if (error.rotatedRefreshToken) {
      // Before the exchange's own save this is that save (replace whatever
      // is stored); after it, it belongs to this attempt's session only.
      return this.saveSession(
        withRefreshToken(
          {
            sessionKey: flow.sessionKey,
            refreshToken: error.rotatedRefreshToken,
            permissions: approvedPermissions,
          },
          error.rotatedRefreshToken,
        ),
        replacedStoredSession ? { sid: sessionId(flow.sessionKey) } : 'any',
        flow.generation,
      ).then(
        () => error,
        (saveError: unknown) => this.afterFailedRecovery(error, saveError),
      );
    }
    return error;
  }

  private async renewOnce(
    options:
      | {
          permissionsSubset?: NativeDelegationPermission[];
          siweNonce?: string;
        }
      | undefined,
    generation: number,
  ): Promise<RenewDelegationResult> {
    const cfg = this.delegation!;
    let reloadedAfterConflict = false;
    for (;;) {
      const session = await this.readCurrentSession(generation);
      if (!session) {
        throw new OpenKeyNativeError('NOT_SIGNED_IN', 'No stored delegation session');
      }
      try {
        const result = await renewDelegation({
          metadata: await this.ensureMetadata(),
          clientId: this.clientId,
          refreshToken: session.refreshToken,
          sessionKey: session.sessionKey,
          requestedPermissions: session.permissions,
          permissionsSubset: options?.permissionsSubset,
          siweNonce: options?.siweNonce,
          expectedTinycloudHost: cfg.tinycloudHost,
          fetchFn: cfg.fetchFn,
          sha256Fn: this.sha256,
          sleepFn: cfg.sleepFn,
        });

        // The SDK verifies the delegation itself (spec). A failure wraps
        // as SERVER carrying the rotated refresh token, which the catch
        // below persists — it is live and the old one is dead.
        await this.verifyDelegationOrThrow(
          result.delegation,
          result.refreshToken,
        );

        // A signOut() during the request or verification invalidated this
        // renewal, and a newer sign-in may have replaced this session:
        // guarded persist re-checks both inside the serialized write and
        // throws NOT_SIGNED_IN; the rotated grant is abandoned (revoked or
        // a pending revoke) rather than written over a wiped or newer
        // session. The approved
        // set is kept as-is: a subset renew must not narrow it.
        await this.saveSession(
          withRefreshToken(session, result.refreshToken),
          { sid: sessionId(session.sessionKey) },
          generation,
        );
        return result;
      } catch (error) {
        if (!(error instanceof OpenKeyNativeError)) throw error;
        // Terminal errors mean the grant is dead: wipe the local session
        // before rethrowing (spec: terminal renew = local sign-out). Only
        // the session this renew started from is wiped; a newer session
        // stored since is left alone. The outcome is final, so a rotated
        // token is not persisted; its grant is abandoned instead.
        if (TERMINAL_SESSION_CODES.has(error.code)) {
          await this.removeSession(session.sessionKey);
          if (error.rotatedRefreshToken) {
            await this.abandonGrant(
              withRefreshToken(session, error.rotatedRefreshToken),
            );
            error.rotatedRefreshToken = undefined;
          }
          throw error;
        }
        // The server already rotated the token: persist it before
        // reporting the error or the session is lost (spec). NOT_SIGNED_IN
        // means signOut() won and nothing may be written.
        if (error.rotatedRefreshToken && error.code !== 'NOT_SIGNED_IN') {
          try {
            await this.saveSession(
              withRefreshToken(session, error.rotatedRefreshToken),
              { sid: sessionId(session.sessionKey) },
              generation,
            );
          } catch (saveError) {
            // The failed save abandoned the token; a storage failure is
            // reported as STORAGE with this error as its cause.
            throw this.afterFailedRecovery(error, saveError);
          }
        }
        if (error.code === 'RENEWAL_CONFLICT' && !reloadedAfterConflict) {
          // Another instance rotated the token first: reload what storage
          // has now and try once with it (spec SDK mapping).
          reloadedAfterConflict = true;
          continue;
        }
        throw error;
      }
    }
  }

  private ensureMetadata(): Promise<OpenKeyServerMetadata> {
    // Don't cache a failed discovery — a transient failure must not poison
    // later sign-ins.
    if (!this.metadataPromise) {
      const discovery: Promise<OpenKeyServerMetadata> = discoverOpenKeyServer(
        this.issuer,
        this.delegation!.fetchFn,
      ).catch((error) => {
        if (this.metadataPromise === discovery) this.metadataPromise = undefined;
        throw error;
      });
      this.metadataPromise = discovery;
    }
    return this.metadataPromise;
  }

  /**
   * The current session for a caller that started in `generation`, read
   * from storage inside the queue (there is no cache). `null` while a
   * signOut() runs (already signed out) or once one has started since
   * `generation` — including one that started while the read was queued.
   * A storage read failure throws a typed `STORAGE` error.
   */
  private async readCurrentSession(
    generation: number,
  ): Promise<DelegationSession | null> {
    const signedOut = () =>
      this.signOutFlights.size > 0 || generation !== this.sessionGeneration;
    if (signedOut()) return null;
    let session: DelegationSession | null;
    try {
      session = await this.runInStorageQueue(() => this.readStoredSession());
    } catch (error) {
      throw this.storageError('read stored delegation session', error);
    }
    return signedOut() ? null : session;
  }

  /**
   * Read the stored session record. Call inside the storage queue. A
   * storage failure throws (nothing is assumed); a record that was read
   * but can't be parsed can never be used or revoked, so it is removed
   * and reads as no session.
   */
  private readStoredSession(): Promise<DelegationSession | null> {
    return this.updateRecord(this.delegationStorageKey, (raw) => {
      const session = parseStoredSession(raw);
      return session === 'corrupt'
        ? { result: null, write: { value: null } }
        : { result: session };
    });
  }

  /**
   * Run `task` inside the storage queue shared by every instance using
   * this store object. Serializes every read and write of the session and
   * pending-revoke records. Tasks must not call runInStorageQueue
   * themselves.
   */
  private runInStorageQueue<T>(task: () => Promise<T>): Promise<T> {
    const storage = this.delegation!.storage;
    let queue = storageQueues.get(storage);
    if (!queue) {
      queue = { tail: Promise.resolve() };
      storageQueues.set(storage, queue);
    }
    const result = queue.tail.then(task, task);
    queue.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  /**
   * One read-decide-write step on a storage key (call inside the storage
   * queue). `decide` sees the current raw value and says what to write.
   * When the store implements `compareAndSet`, the write only lands if the
   * value is still the one `decide` saw; otherwise `decide` runs again on
   * the new value, so a writer outside this queue (another store object or
   * process) is never overwritten blindly. Without `compareAndSet` the
   * write is a plain `set`/`remove`, atomic only with respect to this
   * queue.
   */
  private async updateRecord<T>(
    key: string,
    decide: (raw: string | null) => RecordUpdate<T>,
  ): Promise<T> {
    const storage = this.delegation!.storage;
    for (;;) {
      const raw = await storage.get(key);
      const { result, write } = decide(raw);
      if (!write) return result;
      if (storage.compareAndSet) {
        if (await storage.compareAndSet(key, raw, write.value)) return result;
        continue;
      }
      if (write.value === null) await storage.remove(key);
      else await storage.set(key, write.value);
      return result;
    }
  }

  /**
   * The one compare-and-set every session write and remove goes through.
   * Inside the storage queue it refuses when a signOut() has started since
   * `generation` (when given), then — unless `expect` is `any` — reads the
   * stored record and refuses unless it is the expected session (and
   * refresh token, when pinned). Only then is `next` written, or the record
   * removed when `next` is `null`. Resolves the session the write replaced
   * (read in the same step), or `null`. A refusal writes nothing and throws
   * `NOT_SIGNED_IN` (superseded); a storage failure — including a failure
   * to read the record being replaced — throws as-is.
   */
  private commitSession(
    next: DelegationSession | null,
    expect: SessionExpectation,
    generation?: number,
  ): Promise<DelegationSession | null> {
    return this.runInStorageQueue(() =>
      this.updateRecord(this.delegationStorageKey, (raw) => {
        if (generation !== undefined && generation !== this.sessionGeneration) {
          throw new OpenKeyNativeError(
            'NOT_SIGNED_IN',
            'sign-out since this operation started; result discarded',
          );
        }
        const parsed = parseStoredSession(raw);
        const current = parsed === 'corrupt' ? null : parsed;
        if (
          expect !== 'any' &&
          (!current ||
            sessionId(current.sessionKey) !== expect.sid ||
            (expect.refreshToken !== undefined &&
              current.refreshToken !== expect.refreshToken))
        ) {
          throw new OpenKeyNativeError(
            'NOT_SIGNED_IN',
            'the stored session changed; result discarded',
          );
        }
        return {
          result: current,
          write: { value: next ? serializeSession(next) : null },
        };
      }),
    );
  }

  /**
   * Save a session through commitSession. `expect: 'any'` is a sign-in's
   * save: it first waits for any signOut() in progress, so a sign-in that
   * started after the signOut() lands after it (one that started before is
   * refused by `generation`). A refusal throws `NOT_SIGNED_IN` (without
   * `rotatedRefreshToken`) after abandoning the discarded grant. A storage
   * write failure abandons the grant too — the SDK has no way to take the
   * token back later, so leaving it live would orphan it — and throws
   * `STORAGE` *without* `rotatedRefreshToken`: the token is revoked, or a
   * pending revoke, or (when the pending-revoke write fails as well) its
   * revoke was at least attempted. When a sign-in's save replaces a
   * different session, that session's grant is abandoned once the new one
   * is written.
   */
  private async saveSession(
    session: DelegationSession,
    expect: SessionExpectation,
    generation: number,
  ): Promise<void> {
    if (expect === 'any') {
      while (this.signOutFlights.size > 0) {
        await Promise.allSettled([...this.signOutFlights]);
      }
    }
    let replaced: DelegationSession | null;
    try {
      replaced = await this.commitSession(session, expect, generation);
    } catch (error) {
      if (
        error instanceof OpenKeyNativeError &&
        error.code === 'NOT_SIGNED_IN'
      ) {
        // The token is abandoned (revoked, or a pending revoke), not a
        // recovery token: it does not ride the error.
        await this.abandonGrant(session);
        throw error;
      }
      await this.abandonGrant(session);
      throw new OpenKeyNativeError(
        'STORAGE',
        `failed to persist delegation session; its grant was revoked: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    if (
      replaced &&
      sessionId(replaced.sessionKey) !== sessionId(session.sessionKey)
    ) {
      await this.abandonGrant(replaced);
    }
  }

  /**
   * Remove the stored session if it is still `sessionKey`'s (terminal
   * outcomes); a newer session is left alone. Best-effort: failures are
   * swallowed — the terminal path that calls this must still surface its
   * original error.
   */
  private async removeSession(sessionKey: NativeSessionKeypair): Promise<void> {
    await this.commitSession(null, { sid: sessionId(sessionKey) }).catch(
      () => {},
    );
  }

  /**
   * Run config.verifyDelegation and wrap any failure as SERVER carrying
   * the live refresh token — a failed check means the code/token exchange
   * already happened, so the token must never be dropped silently.
   */
  private async verifyDelegationOrThrow(
    delegation: TinyCloudDelegation,
    liveRefreshToken: string,
  ): Promise<void> {
    try {
      await this.delegation!.verifyDelegation(delegation);
    } catch (error) {
      const wrapped = new OpenKeyNativeError(
        'SERVER',
        `delegation verification failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      wrapped.rotatedRefreshToken = liveRefreshToken;
      throw wrapped;
    }
  }

  /**
   * `OpenKeyError` and `OpenKeyNativeError` pass through (delegation
   * protocol errors need `status`/`retryAfterSeconds`/`rotatedRefreshToken`);
   * anything else becomes `UNKNOWN`.
   */
  private normalizeError(error: unknown): Error {
    if (error instanceof OpenKeyError || error instanceof OpenKeyNativeError) {
      return error;
    }
    return new OpenKeyError(
      'UNKNOWN',
      error instanceof Error ? error.message : String(error),
    );
  }

  /**
   * Plain-mode errors are always `OpenKeyError`. A native code that exists
   * verbatim (`USER_CANCELLED`, `ACCESS_DENIED`, `STATE_MISMATCH`, `SERVER`)
   * is re-mapped onto `OpenKeyError`; every other native code (including
   * `consent_required`) maps to `SERVER` — in plain mode the only OAuth
   * `error=` with its own code is `access_denied`.
   */
  private toPlainError(error: unknown): Error {
    if (error instanceof OpenKeyError) return error;
    if (error instanceof OpenKeyNativeError) {
      return new OpenKeyError(
        PLAIN_CALLBACK_CODES.has(error.code)
          ? (error.code as OpenKeyError['code'])
          : 'SERVER',
        error.message,
      );
    }
    return new OpenKeyError(
      'UNKNOWN',
      error instanceof Error ? error.message : String(error),
    );
  }
}
