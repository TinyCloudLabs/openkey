import type { OpenKeyRNConfig, AuthTokens } from './types';
import { OpenKeyError } from './types';
import type { SHA256Fn } from '@openkey/core';
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  refreshAccessToken,
} from '@openkey/core';

/**
 * A function that opens a URL in the system browser (e.g. via expo-web-browser or react-native Linking).
 * The consumer MUST provide this — there is no default.
 */
export type BrowserOpener = (url: string) => Promise<void>;

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
  /** RFC 9700 resource indicator. When set, access tokens are JWTs with this audience. Defaults to host URL. */
  resource?: string;
}

interface PendingFlow {
  verifier: string;
  resolve: (tokens: AuthTokens) => void;
  reject: (error: OpenKeyError) => void;
}

/**
 * OAuth 2.0 PKCE client for React Native.
 *
 * Usage:
 * 1. Create an instance with your config and a browser opener function.
 * 2. Call `signIn()` — this opens the browser and returns a Promise<AuthTokens>.
 * 3. When your app receives the redirect callback URL, call `handleCallback(url)`.
 * 4. The signIn() promise resolves with the tokens.
 */
export class OpenKeyRN {
  private host: string;
  private clientId: string;
  private redirectUri: string;
  private resource: string;
  private openBrowser: BrowserOpener;
  private sha256?: SHA256Fn;
  private timeoutMs: number;

  private pendingFlows: Map<string, PendingFlow> = new Map();

  constructor(config: OpenKeyRNFullConfig) {
    this.host = config.host;
    this.clientId = config.clientId;
    this.redirectUri = config.redirectUri;
    this.resource = config.resource ?? config.host;
    this.openBrowser = config.openBrowser;
    this.sha256 = config.sha256;
    this.timeoutMs = config.timeoutMs ?? 300_000;
  }

  /**
   * Initiate the OAuth 2.0 Authorization Code + PKCE sign-in flow.
   *
   * Opens the authorization URL in the browser. The returned promise
   * resolves when `handleCallback()` is called with the matching redirect URL,
   * or rejects on timeout / error.
   */
  async signIn(): Promise<AuthTokens> {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier, this.sha256);
    const state = generateState();

    const authUrl = buildAuthorizationUrl({
      host: this.host,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      codeChallenge: challenge,
      state,
      scopes: ['openid', 'email', 'keys', 'offline_access'],
    });

    const tokensPromise = new Promise<AuthTokens>((resolve, reject) => {
      this.pendingFlows.set(state, { verifier, resolve, reject });

      // Set timeout to reject if callback never arrives
      const timer = setTimeout(() => {
        if (this.pendingFlows.has(state)) {
          this.pendingFlows.delete(state);
          reject(new OpenKeyError('TIMEOUT', `Sign-in timed out after ${this.timeoutMs}ms`));
        }
      }, this.timeoutMs);

      // Ensure the timer doesn't keep the Node/Bun process alive.
      // In Node/Bun, setTimeout returns an object with unref(); in browsers it returns a number.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const t = timer as any;
      if (typeof t === 'object' && typeof t.unref === 'function') {
        t.unref();
      }
    });

    await this.openBrowser(authUrl);

    return tokensPromise;
  }

  /**
   * Handle an incoming redirect callback URL.
   *
   * Call this when your app receives a deep link / URL callback from the browser.
   * Returns `true` if the URL was recognized and handled (i.e. it contained a
   * matching `state` from a pending signIn flow), `false` otherwise.
   *
   * The actual token exchange happens asynchronously — the pending `signIn()`
   * promise resolves or rejects based on the exchange result.
   */
  handleCallback(url: string): boolean {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return false;
    }

    const code = parsed.searchParams.get('code');
    const state = parsed.searchParams.get('state');

    if (!code || !state) {
      return false;
    }

    const pending = this.pendingFlows.get(state);
    if (!pending) {
      return false;
    }

    // Remove from pending immediately to prevent double-handling
    this.pendingFlows.delete(state);

    // Fire the token exchange asynchronously — handleCallback returns synchronously
    exchangeAuthorizationCode({
      host: this.host,
      code,
      redirectUri: this.redirectUri,
      clientId: this.clientId,
      codeVerifier: pending.verifier,
      resource: this.resource,
    }).then(
      (tokens) => pending.resolve(tokens),
      (error) => {
        if (error instanceof OpenKeyError) {
          pending.reject(error);
        } else {
          pending.reject(
            new OpenKeyError(
              'UNKNOWN',
              error instanceof Error ? error.message : String(error),
            ),
          );
        }
      },
    );

    return true;
  }

  /**
   * Refresh an access token using a refresh token.
   */
  async refreshToken(refreshTokenValue: string): Promise<AuthTokens> {
    return refreshAccessToken({
      host: this.host,
      refreshToken: refreshTokenValue,
      clientId: this.clientId,
      resource: this.resource,
    });
  }

  /**
   * Sign out by revoking the access token.
   * Also clears all pending sign-in flows.
   */
  async signOut(accessToken: string): Promise<void> {
    // Clear all pending flows
    for (const [state, pending] of this.pendingFlows) {
      pending.reject(new OpenKeyError('USER_CANCELLED', 'Sign-out cancelled pending sign-in'));
      this.pendingFlows.delete(state);
    }

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
}
