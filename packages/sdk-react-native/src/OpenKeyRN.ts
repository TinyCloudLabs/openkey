import type {
  OpenKeyRNConfig,
  OpenKeyRNAuthTokens,
  OpenKeyRNDelegationConfig,
} from './types';
import { OpenKeyError } from './types';
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
  /** Permissions granted on the last delegation; basis for renew subset checks. */
  permissions: NativeDelegationPermission[];
}

/** JSON shape persisted through `OpenKeySecureStore`. */
interface StoredDelegationSession {
  privateJwk: NativeSessionKeypair['privateJwk'];
  refreshToken: string;
  permissions: NativeDelegationPermission[];
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
 * Revoke errors that mean the server-side grant is already unusable:
 * signOut wipes locally and resolves (spec). Anything else (NETWORK,
 * TEMPORARILY_UNAVAILABLE after the internal retry, SERVER, …) still wipes
 * locally but makes signOut reject — the grant may still be active.
 */
const TERMINAL_REVOKE_CODES = new Set(['INVALID_GRANT']);

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

/**
 * Identity for a renew() call's options — concurrent renew()s with the
 * same key share the in-flight promise; different keys queue behind it.
 */
function renewKey(options?: {
  permissionsSubset?: NativeDelegationPermission[];
  siweNonce?: string;
}): string {
  const subset = (options?.permissionsSubset ?? [])
      .map((p) => `${p.service}|${p.space}|${p.path ?? ''}|${p.actions.join(',')}`)
      .join(';');
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
  private openBrowser: BrowserOpener;
  private sha256?: SHA256Fn;
  private timeoutMs: number;

  private pendingFlows: Map<string, PendingFlow> = new Map();
  private metadataPromise?: Promise<OpenKeyServerMetadata>;
  private delegationSession?: DelegationSession;
  private renewInFlight?: Promise<RenewDelegationResult>;
  /** Bumped by signOut(); an in-flight renew checks it before persisting. */
  private sessionGeneration = 0;
  /**
   * Serializes every delegation-session storage mutation (persist + wipe)
   * so a write can never interleave with signOut's wipe. Tasks must not
   * call runInStorageQueue themselves.
   */
  private storageQueue: Promise<unknown> = Promise.resolve();
  /** Options of the in-flight renew; queued callers compare against it. */
  private renewInFlightKey?: string;

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
    this.openBrowser = config.openBrowser;
    this.sha256 = config.sha256;
    this.timeoutMs = config.timeoutMs ?? 300_000;
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
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier, this.sha256);
    const state = generateState();

    let authUrl: string;
    let delegationFlow: PendingDelegationFlow | undefined;

    if (this.delegation) {
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
      authUrl = buildNativeAuthorizeUrl({
        authorizationEndpoint: metadata.authorizationEndpoint,
        clientId: this.clientId,
        requestUri: par.requestUri,
      });
      delegationFlow = {
        sessionKey,
        metadata,
        permissions: cfg.permissions,
        generation: this.sessionGeneration,
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
   * Single-flight, keyed on options: concurrent calls with IDENTICAL
   * `permissionsSubset`/`siweNonce` share one renewal; a call with
   * different options is queued behind the in-flight one, so two renewals
   * never race the same refresh token. Persists the rotated refresh token
   * before resolving; on `RENEWAL_CONFLICT` reloads the stored token and
   * retries once. Terminal errors (`INVALID_GRANT`, `CONSENT_REQUIRED`,
   * `ACCESS_DENIED`, `SPACE_UNAVAILABLE`) wipe the local session before
   * rethrowing (spec: a terminal renew error is a local sign-out). If the
   * server already rotated the token before failing, the rotated token is
   * persisted first and always rides the error as `rotatedRefreshToken`.
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
   * The local session is always wiped. Per the spec, a TERMINAL revoke
   * failure (`invalid_session_proof`/`invalid_grant` → `INVALID_GRANT`)
   * means the grant is already unusable server-side, so signOut resolves.
   * Any other revoke failure (NETWORK, TEMPORARILY_UNAVAILABLE after the
   * internal retry, SERVER) still wipes locally but rejects with the
   * typed error — the server grant may still be active, and the app can
   * retry `signOut()`. A storage wipe failure also rejects.
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
      const session = await this.getDelegationSession().catch(() => null);
      const metadata = session
        ? await this.ensureMetadata().catch(() => null)
        : null;
      if (session && metadata) {
        try {
          await revokeDelegation({
            metadata,
            clientId: this.clientId,
            refreshToken: session.refreshToken,
            sessionKey: session.sessionKey,
            fetchFn: this.delegation.fetchFn,
            sha256Fn: this.sha256,
            sleepFn: this.delegation.sleepFn,
          });
        } catch (error) {
          if (
            error instanceof OpenKeyNativeError &&
            TERMINAL_REVOKE_CODES.has(error.code)
          ) {
            // Grant already unusable server-side (spec).
          } else {
            // Transient/unknown revoke failure: the grant may still be
            // active server-side. Local wipe still runs; the typed error
            // tells the caller to retry signOut().
            firstError = this.normalizeError(error);
          }
        }
      }
      // The wipe is serialized with session persists: nothing can write
      // a session record concurrently with this remove.
      this.delegationSession = undefined;
      try {
        await this.runInStorageQueue(() =>
          this.delegation!.storage.remove(this.delegationStorageKey),
        );
      } catch (error) {
        // The local wipe failed: report it — signOut must not claim
        // success while credentials may persist in secure storage.
        firstError ??= new OpenKeyNativeError(
          'NETWORK',
          `failed to remove stored delegation session: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
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
    try {
      const callback = parseNativeCallback({
        url,
        expectedState: pending.state,
        issuer: this.issuer,
      });

      if (pending.delegation) {
        const cfg = this.delegation!;
        const generation = pending.delegation.generation;
        const result = await exchangeDelegationCode({
          metadata: pending.delegation.metadata,
          code: callback.code,
          redirectUri: this.redirectUri,
          clientId: this.clientId,
          codeVerifier: pending.verifier,
          sessionKey: pending.delegation.sessionKey,
          requestedPermissions: pending.delegation.permissions,
          expectedTinycloudHost: cfg.tinycloudHost,
          fetchFn: cfg.fetchFn,
          sha256Fn: this.sha256,
        });

        // The SDK verifies the delegation itself: siwe + signature must
        // reproduce delegationHeader/delegationCid (spec). If this fails the
        // code was still exchanged, so surface the refresh token on the
        // error — the caller must persist it or the session is lost.
        await this.verifyDelegationOrThrow(
          result.delegation,
          result.refreshToken,
        );

        let session: DelegationSession = {
          sessionKey: pending.delegation.sessionKey,
          refreshToken: result.refreshToken,
          permissions: result.delegation.permissions,
        };
        // Persist BEFORE any immediate renew so the live refresh token is
        // never lost (spec). A signOut() during the exchange invalidates
        // this write; the orphaned grant is revoked best-effort.
        await this.persistSessionGuarded(session, generation, {
          revokeOrphanOnInvalid: {
            metadata: pending.delegation.metadata,
            sessionKey: pending.delegation.sessionKey,
          },
        });

        let delegation = result.delegation;
        // Renew immediately when the returned delegation is already inside
        // the renewal lead window, so signIn never resolves with an
        // almost-expired delegation (spec renewal schedule). On failure the
        // error is surfaced (with rotatedRefreshToken when the server had
        // already rotated) and the initial session stays persisted.
        if (delegationNeedsRenewalNow(delegation)) {
          try {
            const renewed = await renewDelegation({
              metadata: pending.delegation.metadata,
              clientId: this.clientId,
              refreshToken: session.refreshToken,
              sessionKey: pending.delegation.sessionKey,
              requestedPermissions: delegation.permissions,
              expectedTinycloudHost: cfg.tinycloudHost,
              fetchFn: cfg.fetchFn,
              sha256Fn: this.sha256,
              sleepFn: cfg.sleepFn,
            });
            await this.verifyDelegationOrThrow(
              renewed.delegation,
              renewed.refreshToken,
            );
            session = {
              sessionKey: pending.delegation.sessionKey,
              refreshToken: renewed.refreshToken,
              permissions: renewed.delegation.permissions,
            };
            await this.persistSessionGuarded(session, generation);
            delegation = renewed.delegation;
          } catch (error) {
            // Terminal error (grant dead): wipe the just-persisted local
            // session, then let the error reject signIn.
            if (
              error instanceof OpenKeyNativeError &&
              TERMINAL_SESSION_CODES.has(error.code)
            ) {
              await this.wipeLocalSession();
            }
            throw error;
          }
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
      if (pending.delegation) {
        // Terminal errors (grant dead) require a local sign-out (spec).
        if (
          error instanceof OpenKeyNativeError &&
          TERMINAL_SESSION_CODES.has(error.code)
        ) {
          await this.wipeLocalSession();
        }
        // If the code was already exchanged, persist the rotated refresh
        // token before reporting the error — the old token is dead (spec).
        // When persistence itself fails, the caller still needs the token,
        // so the original error (which carries rotatedRefreshToken) is
        // rethrown.
        if (
          error instanceof OpenKeyNativeError &&
          error.rotatedRefreshToken
        ) {
          const session: DelegationSession = {
            sessionKey: pending.delegation.sessionKey,
            refreshToken: error.rotatedRefreshToken,
            permissions: pending.delegation.permissions,
          };
          try {
            await this.persistSessionGuarded(
              session,
              pending.delegation.generation,
            );
            this.delegationSession = session;
          } catch {
            // Keep the original error: it carries rotatedRefreshToken.
          }
        }
      }
      pending.reject(
        pending.delegation
          ? this.normalizeError(error)
          : this.toPlainError(error),
      );
    }
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
      const session = await this.getDelegationSession();
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
        // as SERVER carrying the rotated refresh token — it is live and
        // the old one is dead — and the token is persisted best-effort so
        // the session survives.
        try {
          await cfg.verifyDelegation(result.delegation);
        } catch (verifyError) {
          const wrapped = new OpenKeyNativeError(
            'SERVER',
            `delegation verification failed: ${
              verifyError instanceof Error
                ? verifyError.message
                : String(verifyError)
            }`,
          );
          wrapped.rotatedRefreshToken = result.refreshToken;
          const rescued: DelegationSession = {
            sessionKey: session.sessionKey,
            refreshToken: result.refreshToken,
            permissions: result.delegation.permissions,
          };
          try {
            await this.persistSessionGuarded(rescued, generation);
            if (generation === this.sessionGeneration) {
              this.delegationSession = rescued;
            }
          } catch {
            // The wrapped error still carries rotatedRefreshToken — the
            // caller can persist it themselves.
          }
          throw wrapped;
        }

        // A signOut() during the request or verification invalidated this
        // renewal: guarded persist re-checks the generation inside the
        // serialized write and throws NOT_SIGNED_IN; the rotated token is
        // discarded rather than written over a wiped session.
        const next: DelegationSession = {
          sessionKey: session.sessionKey,
          refreshToken: result.refreshToken,
          permissions: result.delegation.permissions,
        };
        await this.persistSessionGuarded(next, generation);
        this.delegationSession = next;
        return result;
      } catch (error) {
        if (error instanceof OpenKeyNativeError) {
          // The server already rotated the token: persist it before
          // reporting the error or the session is lost (spec).
          if (
            error.rotatedRefreshToken &&
            this.delegationSession?.refreshToken !==
              error.rotatedRefreshToken
          ) {
            const rescued: DelegationSession = {
              ...session,
              refreshToken: error.rotatedRefreshToken,
            };
            try {
              await this.persistSessionGuarded(rescued, generation);
              if (generation === this.sessionGeneration) {
                this.delegationSession = rescued;
              }
            } catch {
              // The thrown error already carries rotatedRefreshToken —
              // the caller can retry persisting it.
            }
          }
          if (error.code === 'RENEWAL_CONFLICT' && !reloadedAfterConflict) {
            // Another instance rotated the token first: reload what storage
            // has now and try once with it (spec SDK mapping).
            reloadedAfterConflict = true;
            this.delegationSession = undefined;
            continue;
          }
          // Terminal errors mean the grant is dead: wipe the local session
          // before rethrowing (spec: terminal renew = local sign-out).
          if (TERMINAL_SESSION_CODES.has(error.code)) {
            await this.wipeLocalSession();
          }
        }
        throw error;
      }
    }
  }


  private ensureMetadata(): Promise<OpenKeyServerMetadata> {
    // Don't cache a failed discovery — a transient failure must not poison
    // later sign-ins.
    this.metadataPromise ??= discoverOpenKeyServer(
      this.issuer,
      this.delegation!.fetchFn,
    ).catch((error) => {
      this.metadataPromise = undefined;
      throw error;
    });
    return this.metadataPromise;
  }

  private async getDelegationSession(): Promise<DelegationSession | null> {
    if (this.delegationSession) return this.delegationSession;
    const cfg = this.delegation;
    if (!cfg) return null;
    const raw = await cfg.storage.get(this.delegationStorageKey);
    if (!raw) return null;
    try {
      const record = JSON.parse(raw) as StoredDelegationSession;
      const session: DelegationSession = {
        sessionKey: sessionKeypairFromJwk(record.privateJwk),
        refreshToken: record.refreshToken,
        permissions: record.permissions,
      };
      this.delegationSession = session;
      return session;
    } catch {
      // Corrupt record: wipe it and report signed-out.
      await cfg.storage.remove(this.delegationStorageKey).catch(() => {});
      return null;
    }
  }

  private async persistDelegationSession(
    session: DelegationSession,
  ): Promise<void> {
    const record: StoredDelegationSession = {
      privateJwk: session.sessionKey.privateJwk,
      refreshToken: session.refreshToken,
      permissions: session.permissions,
    };
    await this.delegation!.storage.set(
      this.delegationStorageKey,
      JSON.stringify(record),
    );
  }

  /**
   * Run `task` inside the storage mutex. Serializes every delegation-session
   * storage mutation so a write can never interleave with signOut's wipe.
   */
  private runInStorageQueue<T>(task: () => Promise<T>): Promise<T> {
    const result = this.storageQueue.then(task, task);
    this.storageQueue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  /**
   * Persist a session inside the storage mutex, re-checking the session
   * generation inside the serialized section (a signOut that lands between
   * the network call and the write wins: the write is skipped and
   * NOT_SIGNED_IN is thrown — with `rotatedRefreshToken` set so callers
   * can still recover the live token). Storage failures surface as
   * NETWORK carrying the same token.
   *
   * `revokeOrphanOnInvalid`: used by the code-exchange path — a discarded
   * session leaves a live grant the client will never see again, so it is
   * revoked best-effort (spec's signOut revoke path).
   */
  private async persistSessionGuarded(
    session: DelegationSession,
    generation: number,
    opts?: {
      revokeOrphanOnInvalid?: {
        metadata: OpenKeyServerMetadata;
        sessionKey: NativeSessionKeypair;
      };
    },
  ): Promise<void> {
    try {
      await this.runInStorageQueue(async () => {
        if (generation !== this.sessionGeneration) {
          const invalid = new OpenKeyNativeError(
            'NOT_SIGNED_IN',
            'sign-out during sign-in/renewal; session discarded',
          );
          invalid.rotatedRefreshToken = session.refreshToken;
          throw invalid;
        }
        await this.persistDelegationSession(session);
      });
    } catch (error) {
      if (
        error instanceof OpenKeyNativeError &&
        error.code === 'NOT_SIGNED_IN'
      ) {
        if (opts?.revokeOrphanOnInvalid) {
          const cfg = this.delegation!;
          await revokeDelegation({
            metadata: opts.revokeOrphanOnInvalid.metadata,
            clientId: this.clientId,
            refreshToken: session.refreshToken,
            sessionKey: opts.revokeOrphanOnInvalid.sessionKey,
            fetchFn: cfg.fetchFn,
            sha256Fn: this.sha256,
            sleepFn: cfg.sleepFn,
          }).catch(() => {
            // Best-effort: the revoke can also fail transiently; the
            // grant dies with its delegation TTL either way.
          });
        }
        throw error;
      }
      const wrapped = new OpenKeyNativeError(
        'NETWORK',
        `failed to persist delegation session: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      wrapped.rotatedRefreshToken = session.refreshToken;
      throw wrapped;
    }
  }

  /**
   * Wipe the stored session inside the storage mutex. Best-effort: wipe
   * failures are swallowed — the terminal path that calls this must still
   * surface its original error.
   */
  private async wipeLocalSession(): Promise<void> {
    this.delegationSession = undefined;
    await this.runInStorageQueue(() =>
      this.delegation!.storage.remove(this.delegationStorageKey),
    ).catch(() => {});
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
