// OpenKey SDK - Browser client for third-party apps
// Provides "Sign with OpenKey" functionality via popup or iframe

export interface EIP1193Provider {
  request(args: { method: string; params?: any[] }): Promise<any>;
}

interface EIP6963ProviderInfo {
  uuid: string;
  name: string;
  icon: string;
  rdns: string;
}

interface EIP6963ProviderDetail {
  info: EIP6963ProviderInfo;
  provider: EIP1193Provider;
}

export interface OpenKeyConfig {
  /** OpenKey host URL (default: https://openkey.so) */
  host?: string;
  /** App identifier for display */
  appName?: string;
  /** Use popup instead of iframe (default: true) */
  usePopup?: boolean;
  /** App-provided wallet provider for external key signing */
  externalProvider?: EIP1193Provider;
}

export interface SignMessageRequest {
  message: string;
  keyId?: string; // If not provided, user selects
}

export interface SignTypedDataRequest {
  domain: {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: string;
  };
  types: Record<string, Array<{ name: string; type: string }>>;
  primaryType: string;
  message: Record<string, unknown>;
  keyId?: string;
}

export interface SignResult {
  signature: string;
  address: string;
}

export interface AuthResult {
  address: string;
  keyId: string;
  keyType: 'MANAGED' | 'EXTERNAL';
}

export interface OpenKeyError {
  code: 'USER_CANCELLED' | 'POPUP_BLOCKED' | 'TIMEOUT' | 'NO_KEY' | 'UNAUTHORIZED' | 'UNKNOWN' | 'STATE_MISMATCH';
  message: string;
}

// ======= OAuth 2.1 Types =======

/** OAuth configuration for third-party apps */
export interface OAuthConfig {
  /** OAuth client_id (registered with OpenKey) */
  clientId: string;
  /** Redirect URI (must match registered URI) */
  redirectUri: string;
  /** State parameter for CSRF protection (auto-generated if not provided) */
  state?: string;
}

/** Result from OAuth authorization */
export interface OAuthResult {
  /** Authorization code (exchange for tokens) */
  code: string;
  /** State parameter (verify matches request) */
  state: string;
}

/** Response from token exchange */
export interface OAuthTokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  id_token: string;
  scope: string;
  refresh_token?: string;
}

type MessageType =
  | { type: 'openkey:auth:request'; appName: string }
  | { type: 'openkey:auth:response'; success: true; address: string; keyId: string; keyType?: 'MANAGED' | 'EXTERNAL' }
  | { type: 'openkey:auth:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:sign:request'; message: string; keyId?: string }
  | { type: 'openkey:sign:response'; success: true; signature: string; address: string }
  | { type: 'openkey:sign:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:signTypedData:request'; data: SignTypedDataRequest }
  | { type: 'openkey:signTypedData:response'; success: true; signature: string; address: string }
  | { type: 'openkey:signTypedData:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:link-wallet:request' }
  | { type: 'openkey:link-wallet:response'; success: true; address: string; keyId: string }
  | { type: 'openkey:link-wallet:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:ready' }
  | { type: 'openkey:close' };

const DEFAULT_HOST = 'https://openkey.so';
const POPUP_WIDTH = 400;
const POPUP_HEIGHT = 600;
const DEFAULT_TIMEOUT = 5 * 60 * 1000; // 5 minutes
const OAUTH_STORAGE_KEY = 'openkey_oauth';

// ======= PKCE Utilities =======

function base64UrlEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function generateCodeVerifier(): Promise<string> {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

export class OpenKey {
  private host: string;
  private appName: string;
  private usePopup: boolean;
  private config: OpenKeyConfig;
  private popup: Window | null = null;
  private iframe: HTMLIFrameElement | null = null;
  private lastAuth: AuthResult | null = null;
  private discoveredProviders: EIP6963ProviderDetail[] = [];

  constructor(config: OpenKeyConfig = {}) {
    this.config = config;
    this.host = config.host || DEFAULT_HOST;
    this.appName = config.appName || window.location.hostname;
    this.usePopup = config.usePopup ?? true;

    // Listen for EIP-6963 wallet announcements
    if (typeof window !== 'undefined') {
      this.discoveredProviders = [];
      window.addEventListener('eip6963:announceProvider', (event: any) => {
        this.discoveredProviders.push(event.detail);
      });
      window.dispatchEvent(new Event('eip6963:requestProvider'));
    }
  }

  /**
   * Connect to OpenKey and get user's wallet address
   * Opens auth flow for user to select/create a key
   */
  async connect(): Promise<AuthResult> {
    const result = await this.openFlow<AuthResult>('connect', {
      type: 'openkey:auth:request',
      appName: this.appName,
    });
    this.lastAuth = result;
    return result;
  }

  /**
   * Link an external wallet to the user's OpenKey account
   * Opens link-wallet widget flow
   */
  async linkWallet(): Promise<{ address: string; keyId: string }> {
    return this.openFlow<{ address: string; keyId: string }>('link-wallet', {
      type: 'openkey:link-wallet:request',
    });
  }

  /**
   * Sign a message with the user's OpenKey wallet
   * For external keys, routes directly to the user's wallet provider
   */
  async signMessage(request: SignMessageRequest): Promise<SignResult> {
    if (this.lastAuth?.keyType === 'EXTERNAL') {
      return this.signWithExternalWallet(request);
    }
    return this.signWithPopup(request);
  }

  /**
   * Sign typed data (EIP-712) with the user's OpenKey wallet
   * For external keys, routes directly to the user's wallet provider
   */
  async signTypedData(request: SignTypedDataRequest): Promise<SignResult> {
    if (this.lastAuth?.keyType === 'EXTERNAL') {
      return this.signTypedDataWithExternalWallet(request);
    }
    return this.signTypedDataWithPopup(request);
  }

  /**
   * Find a wallet provider that controls the given address.
   * Checks: 1) app-provided externalProvider, 2) EIP-6963 discovered wallets, 3) window.ethereum
   */
  async findWalletProvider(targetAddress: string): Promise<EIP1193Provider> {
    // 1. Try app-provided externalProvider first
    if (this.config.externalProvider) {
      return this.config.externalProvider;
    }

    // 2. Use EIP-6963 to discover wallets
    for (const { provider } of this.discoveredProviders) {
      try {
        const accounts = await provider.request({ method: 'eth_accounts' }) as string[];
        if (accounts.some(a => a.toLowerCase() === targetAddress.toLowerCase())) {
          return provider;
        }
      } catch {}
    }

    // 3. Fall back to window.ethereum
    if (typeof window !== 'undefined' && (window as any).ethereum) {
      return (window as any).ethereum;
    }

    throw new Error('No wallet provider found for external key. Connect your wallet.');
  }

  private async signWithExternalWallet(request: SignMessageRequest): Promise<SignResult> {
    const provider = await this.findWalletProvider(this.lastAuth!.address);
    const hexMessage = this.toHex(request.message);
    const signature = await provider.request({
      method: 'personal_sign',
      params: [hexMessage, this.lastAuth!.address],
    });
    return { signature: signature as string, address: this.lastAuth!.address };
  }

  private async signTypedDataWithExternalWallet(request: SignTypedDataRequest): Promise<SignResult> {
    const provider = await this.findWalletProvider(this.lastAuth!.address);
    const signature = await provider.request({
      method: 'eth_signTypedData_v4',
      params: [this.lastAuth!.address, JSON.stringify(request)],
    });
    return { signature: signature as string, address: this.lastAuth!.address };
  }

  private signWithPopup(request: SignMessageRequest): Promise<SignResult> {
    return this.openFlow<SignResult>('sign', {
      type: 'openkey:sign:request',
      message: request.message,
      keyId: request.keyId,
    });
  }

  private signTypedDataWithPopup(request: SignTypedDataRequest): Promise<SignResult> {
    return this.openFlow<SignResult>('sign-typed-data', {
      type: 'openkey:signTypedData:request',
      data: request,
    });
  }

  private toHex(str: string): string {
    return '0x' + Array.from(new TextEncoder().encode(str)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Check if user is already authenticated
   */
  async isConnected(): Promise<boolean> {
    // Check for existing session via API
    try {
      const res = await fetch(`${this.host}/api/auth/session`, {
        credentials: 'include',
      });
      if (!res.ok) return false;
      const data = await res.json();
      return !!data.user;
    } catch {
      return false;
    }
  }

  // ======= OAuth 2.1 Provider Methods =======

  /**
   * OAuth 2.1 methods for third-party app authentication
   * Use this when your app has registered OAuth client credentials with OpenKey
   */
  oauth = {
    /**
     * Start OAuth authorization flow
     * Opens popup/redirect to OpenKey authorization endpoint
     * @returns Promise that resolves with authorization code after user consent
     */
    connect: async (config: OAuthConfig): Promise<OAuthResult> => {
      // Generate PKCE values
      const verifier = await generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const state = config.state || generateState();

      // Store for later token exchange
      sessionStorage.setItem(
        OAUTH_STORAGE_KEY,
        JSON.stringify({ verifier, state })
      );

      // Build authorization URL
      const authUrl = new URL(`${this.host}/api/auth/oauth2/authorize`);
      authUrl.searchParams.set('client_id', config.clientId);
      authUrl.searchParams.set('redirect_uri', config.redirectUri);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', 'openid');
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('code_challenge', challenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      return this.openOAuthFlow(authUrl.toString(), state, config.redirectUri);
    },

    /**
     * Exchange authorization code for tokens
     * Call this after receiving the callback with authorization code
     * @param code - Authorization code from callback URL
     * @param config - Same config used for connect()
     * @returns Promise that resolves with access_token, id_token, etc.
     */
    exchangeCode: async (
      code: string,
      config: OAuthConfig
    ): Promise<OAuthTokenResponse> => {
      const stored = sessionStorage.getItem(OAUTH_STORAGE_KEY);
      if (!stored) {
        throw new Error('No PKCE verifier found. Start a new OAuth flow.');
      }

      const { verifier } = JSON.parse(stored);

      const response = await fetch(`${this.host}/api/auth/oauth2/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: config.redirectUri,
          client_id: config.clientId,
          code_verifier: verifier,
        }),
      });

      // Clear stored verifier
      sessionStorage.removeItem(OAUTH_STORAGE_KEY);

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error_description || 'Token exchange failed');
      }

      return response.json();
    },

    /**
     * Verify state parameter from callback
     * Call this before exchangeCode to prevent CSRF attacks
     * @param receivedState - State parameter from callback URL
     * @returns true if state matches, false otherwise
     */
    verifyState: (receivedState: string): boolean => {
      const stored = sessionStorage.getItem(OAUTH_STORAGE_KEY);
      if (!stored) return false;
      const { state } = JSON.parse(stored);
      return state === receivedState;
    },

    /**
     * Parse authorization response from callback URL
     * @param url - Callback URL (defaults to current window.location.href)
     * @returns Parsed code and state, or error
     */
    parseCallback: (
      url?: string
    ): { code: string; state: string } | { error: string; errorDescription?: string } => {
      const urlObj = new URL(url || window.location.href);
      const error = urlObj.searchParams.get('error');

      if (error) {
        return {
          error,
          errorDescription: urlObj.searchParams.get('error_description') || undefined,
        };
      }

      const code = urlObj.searchParams.get('code');
      const state = urlObj.searchParams.get('state');

      if (!code || !state) {
        return { error: 'missing_params', errorDescription: 'Missing code or state parameter' };
      }

      return { code, state };
    },
  };

  private openOAuthFlow(
    url: string,
    state: string,
    redirectUri: string
  ): Promise<OAuthResult> {
    return new Promise((resolve, reject) => {
      if (this.usePopup) {
        this.openOAuthPopup(url, state, redirectUri, resolve, reject);
      } else {
        // Full page redirect - won't resolve, page navigates away
        window.location.href = url;
      }
    });
  }

  private openOAuthPopup(
    url: string,
    state: string,
    redirectUri: string,
    resolve: (value: OAuthResult) => void,
    reject: (error: OpenKeyError) => void
  ) {
    const left = window.screenX + (window.outerWidth - POPUP_WIDTH) / 2;
    const top = window.screenY + (window.outerHeight - POPUP_HEIGHT) / 2;

    this.popup = window.open(
      url,
      'openkey-oauth',
      `width=${POPUP_WIDTH},height=${POPUP_HEIGHT},left=${left},top=${top},popup=true`
    );

    if (!this.popup) {
      reject({
        code: 'POPUP_BLOCKED',
        message: 'Popup was blocked. Please allow popups or use redirect mode.',
      });
      return;
    }

    const redirectHost = new URL(redirectUri).origin;

    // Poll for redirect back with code
    const pollInterval = setInterval(() => {
      try {
        if (this.popup?.closed) {
          clearInterval(pollInterval);
          clearTimeout(timeout);
          reject({
            code: 'USER_CANCELLED',
            message: 'User closed the popup',
          });
          return;
        }

        // Check if redirected to callback URL
        const popupUrl = this.popup?.location?.href;
        if (popupUrl && popupUrl.startsWith(redirectHost)) {
          clearInterval(pollInterval);
          clearTimeout(timeout);

          const urlObj = new URL(popupUrl);
          const code = urlObj.searchParams.get('code');
          const returnedState = urlObj.searchParams.get('state');
          const error = urlObj.searchParams.get('error');

          this.popup?.close();

          if (error) {
            reject({
              code: 'UNAUTHORIZED',
              message: urlObj.searchParams.get('error_description') || error,
            });
            return;
          }

          if (returnedState !== state) {
            reject({
              code: 'STATE_MISMATCH',
              message: 'State mismatch - possible CSRF attack',
            });
            return;
          }

          if (code) {
            resolve({ code, state: returnedState });
          } else {
            reject({
              code: 'UNAUTHORIZED',
              message: 'Authorization failed - no code returned',
            });
          }
        }
      } catch {
        // Cross-origin - popup still on OpenKey domain, continue polling
      }
    }, 100);

    // Timeout
    const timeout = setTimeout(() => {
      clearInterval(pollInterval);
      this.popup?.close();
      reject({
        code: 'TIMEOUT',
        message: 'OAuth flow timed out',
      });
    }, DEFAULT_TIMEOUT);
  }

  private async openFlow<T>(action: string, message: object): Promise<T> {
    return new Promise((resolve, reject) => {
      const url = `${this.host}/widget/${action}?origin=${encodeURIComponent(window.location.origin)}`;

      if (this.usePopup) {
        this.openPopup(url, message, resolve, reject);
      } else {
        this.openIframe(url, message, resolve, reject);
      }
    });
  }

  private openPopup<T>(
    url: string,
    message: object,
    resolve: (value: T) => void,
    reject: (error: OpenKeyError) => void
  ) {
    // Calculate popup position
    const left = window.screenX + (window.outerWidth - POPUP_WIDTH) / 2;
    const top = window.screenY + (window.outerHeight - POPUP_HEIGHT) / 2;

    this.popup = window.open(
      url,
      'openkey',
      `width=${POPUP_WIDTH},height=${POPUP_HEIGHT},left=${left},top=${top},popup=true`
    );

    if (!this.popup) {
      reject({
        code: 'POPUP_BLOCKED',
        message: 'Popup was blocked. Please allow popups for this site.',
      });
      return;
    }

    const cleanup = () => {
      window.removeEventListener('message', handleMessage);
      clearInterval(pollClosed);
      clearTimeout(timeout);
    };

    // Poll to detect popup close
    const pollClosed = setInterval(() => {
      if (this.popup?.closed) {
        cleanup();
        reject({
          code: 'USER_CANCELLED',
          message: 'User closed the popup',
        });
      }
    }, 500);

    // Timeout
    const timeout = setTimeout(() => {
      cleanup();
      this.popup?.close();
      reject({
        code: 'TIMEOUT',
        message: 'Request timed out',
      });
    }, DEFAULT_TIMEOUT);

    // Listen for messages
    const handleMessage = (event: MessageEvent) => {
      if (event.origin !== this.host) return;

      const data = event.data as MessageType;

      if (data.type === 'openkey:ready') {
        // Widget is ready, send our request
        this.popup?.postMessage(message, this.host);
        return;
      }

      if (data.type === 'openkey:close') {
        cleanup();
        this.popup?.close();
        reject({
          code: 'USER_CANCELLED',
          message: 'User cancelled the request',
        });
        return;
      }

      // Handle responses
      if (
        data.type === 'openkey:auth:response' ||
        data.type === 'openkey:sign:response' ||
        data.type === 'openkey:signTypedData:response' ||
        data.type === 'openkey:link-wallet:response'
      ) {
        cleanup();
        this.popup?.close();

        if (data.success) {
          if (data.type === 'openkey:auth:response') {
            resolve({ address: data.address, keyId: data.keyId, keyType: data.keyType || 'MANAGED' } as T);
          } else if (data.type === 'openkey:link-wallet:response') {
            resolve({ address: data.address, keyId: data.keyId } as T);
          } else {
            resolve({ signature: data.signature, address: data.address } as T);
          }
        } else {
          reject(data.error);
        }
      }
    };

    window.addEventListener('message', handleMessage);
  }

  private openIframe<T>(
    url: string,
    message: object,
    resolve: (value: T) => void,
    reject: (error: OpenKeyError) => void
  ) {
    // Create overlay
    const overlay = document.createElement('div');
    overlay.style.cssText = `
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 999999;
    `;

    // Create iframe container
    const container = document.createElement('div');
    container.style.cssText = `
      width: ${POPUP_WIDTH}px;
      height: ${POPUP_HEIGHT}px;
      background: #1a1a1a;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    `;

    // Create iframe
    this.iframe = document.createElement('iframe');
    this.iframe.src = url;
    this.iframe.style.cssText = `
      width: 100%;
      height: 100%;
      border: none;
    `;

    container.appendChild(this.iframe);
    overlay.appendChild(container);
    document.body.appendChild(overlay);

    const cleanup = () => {
      window.removeEventListener('message', handleMessage);
      clearTimeout(timeout);
      overlay.remove();
      this.iframe = null;
    };

    // Close on overlay click
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        cleanup();
        reject({
          code: 'USER_CANCELLED',
          message: 'User cancelled the request',
        });
      }
    });

    // Timeout
    const timeout = setTimeout(() => {
      cleanup();
      reject({
        code: 'TIMEOUT',
        message: 'Request timed out',
      });
    }, DEFAULT_TIMEOUT);

    // Listen for messages
    const handleMessage = (event: MessageEvent) => {
      if (event.origin !== this.host) return;

      const data = event.data as MessageType;

      if (data.type === 'openkey:ready') {
        this.iframe?.contentWindow?.postMessage(message, this.host);
        return;
      }

      if (data.type === 'openkey:close') {
        cleanup();
        reject({
          code: 'USER_CANCELLED',
          message: 'User cancelled the request',
        });
        return;
      }

      // Handle responses
      if (
        data.type === 'openkey:auth:response' ||
        data.type === 'openkey:sign:response' ||
        data.type === 'openkey:signTypedData:response' ||
        data.type === 'openkey:link-wallet:response'
      ) {
        cleanup();

        if (data.success) {
          if (data.type === 'openkey:auth:response') {
            resolve({ address: data.address, keyId: data.keyId, keyType: data.keyType || 'MANAGED' } as T);
          } else if (data.type === 'openkey:link-wallet:response') {
            resolve({ address: data.address, keyId: data.keyId } as T);
          } else {
            resolve({ signature: data.signature, address: data.address } as T);
          }
        } else {
          reject(data.error);
        }
      }
    };

    window.addEventListener('message', handleMessage);
  }

  /**
   * Disconnect and close any open flows
   */
  disconnect() {
    this.popup?.close();
    this.popup = null;
    this.iframe?.parentElement?.parentElement?.remove();
    this.iframe = null;
  }
}

/**
 * Unified EIP-1193 provider that wraps an OpenKey instance.
 * Transparently routes signing to either OpenKey (managed keys) or the user's
 * wallet (external keys).
 */
export class OpenKeyEIP1193Provider implements EIP1193Provider {
  private openkey: OpenKey;
  private address: string;
  private keyId: string;
  private keyType: 'MANAGED' | 'EXTERNAL';

  constructor(openkey: OpenKey, authResult: AuthResult) {
    this.openkey = openkey;
    this.address = authResult.address;
    this.keyId = authResult.keyId;
    this.keyType = authResult.keyType;
  }

  async request({ method, params }: { method: string; params?: any[] }): Promise<any> {
    switch (method) {
      case 'eth_accounts':
      case 'eth_requestAccounts':
        return [this.address];

      case 'eth_chainId':
        return '0x1'; // mainnet

      case 'personal_sign': {
        if (this.keyType === 'EXTERNAL') {
          const provider = await this.openkey.findWalletProvider(this.address);
          return provider.request({ method, params });
        }
        // Managed key: route through OpenKey
        const message = this.hexToString(params![0] as string);
        const result = await this.openkey.signMessage({ message, keyId: this.keyId });
        return result.signature;
      }

      case 'eth_signTypedData_v4': {
        if (this.keyType === 'EXTERNAL') {
          const provider = await this.openkey.findWalletProvider(this.address);
          return provider.request({ method, params });
        }
        const data = JSON.parse(params![1] as string);
        const result = await this.openkey.signTypedData(data);
        return result.signature;
      }

      default:
        throw new Error(`Unsupported method: ${method}`);
    }
  }

  private hexToString(hex: string): string {
    const bytes = new Uint8Array(
      (hex.startsWith('0x') ? hex.slice(2) : hex).match(/.{1,2}/g)!.map(b => parseInt(b, 16))
    );
    return new TextDecoder().decode(bytes);
  }
}

// Default export for convenience
export default OpenKey;

// Create singleton instance
let defaultInstance: OpenKey | null = null;

export function getOpenKey(config?: OpenKeyConfig): OpenKey {
  if (!defaultInstance || config) {
    defaultInstance = new OpenKey(config);
  }
  return defaultInstance;
}
