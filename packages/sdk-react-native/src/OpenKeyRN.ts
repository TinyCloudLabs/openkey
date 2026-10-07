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
}

interface PendingFlow {
  state: string;
  verifier: string;
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

const CALLBACK_PARAMS = ['code', 'error', 'state', 'iss'] as const;

/** Native codes that exist on OpenKeyErrorCode verbatim (plain mode). */
const PLAIN_CALLBACK_CODES = new Set([
  'USER_CANCELLED',
  'ACCESS_DENIED',
  'STATE_MISMATCH',
  'SERVER',
]);

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

  constructor(config: OpenKeyRNFullConfig) {
    this.host = config.host;
    this.clientId = config.clientId;
    this.redirectUri = config.redirectUri;
    this.issuer = config.issuer ?? `${this.host.replace(/\/+$/, '')}/api/auth`;
    this.scopes = config.scopes ?? [
      'openid',
      'email',
      'keys',
      'offline_access',
    ];
    this.resource = config.resource;
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
      delegationFlow = { sessionKey, metadata, permissions: cfg.permissions };
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
      const pending = this.pendingFlows.get(state);
      if (pending) {
        this.pendingFlows.delete(state);
        pending.reject(this.normalizeError(error));
      }
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
   * promise resolves or rejects based on the exchange result. Callbacks with
   * a `state` or `iss` mismatch reject the pending flow with
   * `STATE_MISMATCH`; `error=access_denied` rejects it with `ACCESS_DENIED`
   * and any other `error` with `SERVER`.
   */
  handleCallback(url: string): boolean {
    const params = extractCallbackParams(url);
    if (!params) return false;

    const state = params.get('state');
    let pending = state ? this.pendingFlows.get(state) : undefined;

    if (!pending) {
      // No flow for this state. When exactly one flow is pending, attribute
      // the callback to it so a mismatched `state`/`iss` settles it with
      // STATE_MISMATCH instead of dangling until the timeout.
      if (this.pendingFlows.size !== 1) return false;
      pending = this.pendingFlows.values().next().value!;
    }

    // Remove from pending immediately to prevent double-handling
    this.pendingFlows.delete(pending.state);

    void this.settleFlowFromCallback(pending, url);
    return true;
  }

  /**
   * Refresh an access token using a refresh token.
   */
  async refreshToken(refreshTokenValue: string): Promise<OpenKeyRNAuthTokens> {
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
   * Single-flight: concurrent calls share one renewal. Persists the rotated
   * refresh token before resolving; on `RENEWAL_CONFLICT` reloads the stored
   * token and retries once; if renewal fails after the server already
   * rotated the token, the rotated token is persisted before the error is
   * rethrown (`OpenKeyNativeError`).
   */
  async renew(options?: {
    permissionsSubset?: NativeDelegationPermission[];
    siweNonce?: string;
  }): Promise<RenewDelegationResult> {
    const cfg = this.delegation;
    if (!cfg) {
      throw new OpenKeyNativeError(
        'UNAVAILABLE',
        'renew() requires config.delegation',
      );
    }
    this.renewInFlight ??= this.renewOnce(options)
      .finally(() => {
        this.renewInFlight = undefined;
      });
    return this.renewInFlight;
  }

  /**
   * Sign out: revoke the delegation grant (delegation mode), clear pending
   * sign-in flows, and — when `accessToken` is given — revoke it through the
   * legacy `/api/auth/revoke` endpoint.
   *
   * Delegation revoke failures are swallowed: a terminal failure means the
   * grant is already unusable server-side, and the local session is wiped
   * regardless.
   */
  async signOut(accessToken?: string): Promise<void> {
    // Clear all pending flows
    for (const [state, pending] of this.pendingFlows) {
      pending.reject(new OpenKeyError('USER_CANCELLED', 'Sign-out cancelled pending sign-in'));
      this.pendingFlows.delete(state);
    }

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
        } catch {
          // Terminal revoke failure: grant is already unusable (spec).
        }
      }
      this.delegationSession = undefined;
      await this.delegation.storage
        .remove(this.delegationStorageKey)
        .catch(() => {});
    }

    if (accessToken === undefined) return;

    const body = new URLSearchParams({
      token: accessToken,
    });

    try {
      const response = await fetch(`${this.host}/api/auth/revoke`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
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
      if (error instanceof OpenKeyError) {
        throw error;
      }
      throw new OpenKeyError(
        'NETWORK_ERROR',
        error instanceof Error ? error.message : 'Network request failed',
      );
    }
  }

  // ======= Internals =======

  private registerPendingFlow(
    state: string,
    verifier: string,
    delegation?: PendingDelegationFlow,
  ): Promise<OpenKeyRNAuthTokens> {
    return new Promise<OpenKeyRNAuthTokens>((resolve, reject) => {
      this.pendingFlows.set(state, { state, verifier, delegation, resolve, reject });

      // Set timeout to reject if callback never arrives
      const timer = setTimeout(() => {
        if (this.pendingFlows.has(state)) {
          this.pendingFlows.delete(state);
          reject(new OpenKeyError('TIMEOUT', `Sign-in timed out after ${this.timeoutMs}ms`));
        }
      }, this.timeoutMs);

      // Ensure the timer doesn't keep the Node/Bun process alive.
      // In Node/Bun, setTimeout returns an object with unref(); in browsers it returns a number.
      const t: unknown = timer;
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
   * Settle a pending flow from the opener's return value.
   * `void` (legacy opener) leaves the flow to the deep-link path / timeout.
   */
  private settleFromOpenerResult(
    state: string,
    result: BrowserResult | void,
  ): void {
    if (!result) return;
    if (result.type === 'success' && result.url) {
      // handleCallback consumes the pending flow when the URL parses.
      this.handleCallback(result.url);
      return;
    }
    // Any non-success, defined result ('cancel', 'dismiss', 'locked', …)
    // means the auth session produced no callback: settle immediately.
    const pending = this.pendingFlows.get(state);
    if (pending) {
      this.pendingFlows.delete(state);
      pending.reject(
        new OpenKeyError(
          'USER_CANCELLED',
          `Sign-in was cancelled (browser result: ${result.type})`,
        ),
      );
    }
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
        const session: DelegationSession = {
          sessionKey: pending.delegation.sessionKey,
          refreshToken: result.refreshToken,
          permissions: result.delegation.permissions,
        };
        this.delegationSession = session;
        // Best-effort: an in-memory session still works until restart.
        await this.persistDelegationSession(session).catch(() => {});
        pending.resolve({
          accessToken: result.accessToken,
          // The native flow issues no ID token; keep the AuthTokens shape.
          idToken: '',
          refreshToken: result.refreshToken,
          expiresIn: result.expiresIn ?? 0,
          delegation: result.delegation,
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
      // If the code was already exchanged, persist the rotated refresh token
      // before reporting the error — the old token is dead (spec).
      if (
        error instanceof OpenKeyNativeError &&
        error.rotatedRefreshToken &&
        pending.delegation
      ) {
        const session: DelegationSession = {
          sessionKey: pending.delegation.sessionKey,
          refreshToken: error.rotatedRefreshToken,
          permissions: pending.delegation.permissions,
        };
        this.delegationSession = session;
        await this.persistDelegationSession(session).catch(() => {});
      }
      pending.reject(
        pending.delegation
          ? this.normalizeError(error)
          : this.toPlainError(error),
      );
    }
  }

  private async renewOnce(options?: {
    permissionsSubset?: NativeDelegationPermission[];
    siweNonce?: string;
  }): Promise<RenewDelegationResult> {
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
        const next: DelegationSession = {
          sessionKey: session.sessionKey,
          refreshToken: result.refreshToken,
          permissions: result.delegation.permissions,
        };
        this.delegationSession = next;
        await this.persistDelegationSession(next).catch(() => {});
        return result;
      } catch (error) {
        if (error instanceof OpenKeyNativeError) {
          // The server already rotated the token: persist it before
          // reporting the error or the session is lost (spec).
          if (error.rotatedRefreshToken) {
            const next: DelegationSession = {
              ...session,
              refreshToken: error.rotatedRefreshToken,
            };
            this.delegationSession = next;
            await this.persistDelegationSession(next).catch(() => {});
          }
          if (error.code === 'RENEWAL_CONFLICT' && !reloadedAfterConflict) {
            // Another instance rotated the token first: reload what storage
            // has now and try once with it (spec SDK mapping).
            reloadedAfterConflict = true;
            this.delegationSession = undefined;
            continue;
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
   * is re-mapped onto `OpenKeyError`; anything else becomes `UNKNOWN`.
   */
  private toPlainError(error: unknown): Error {
    if (error instanceof OpenKeyError) return error;
    if (
      error instanceof OpenKeyNativeError &&
      PLAIN_CALLBACK_CODES.has(error.code)
    ) {
      return new OpenKeyError(
        error.code as OpenKeyError['code'],
        error.message,
      );
    }
    return new OpenKeyError(
      'UNKNOWN',
      error instanceof Error ? error.message : String(error),
    );
  }
}
