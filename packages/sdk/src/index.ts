// OpenKey SDK - Browser client for third-party apps
// Provides "Sign with OpenKey" functionality via popup or iframe

import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  buildAuthorizationUrl,
} from '@openkey/core';

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

export type OpenKeyMode = 'iframe' | 'popup' | 'redirect';

export interface OpenKeyConfig {
  /** OpenKey host URL (default: https://openkey.so) */
  host?: string;
  /** OAuth API host URL (default: derived from host by prefixing 'api.') */
  oauthHost?: string;
  /** App identifier for display */
  appName?: string;
  /** UI mode: 'iframe' (default), 'popup', or 'redirect' */
  mode?: OpenKeyMode;
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
  | { type: 'openkey:auth:response'; success: true; address: string; keyId: string; keyType?: 'MANAGED' | 'EXTERNAL'; sessionToken?: string }
  | { type: 'openkey:auth:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:sign:request'; message: string; keyId?: string; sessionToken?: string }
  | { type: 'openkey:sign:response'; success: true; signature: string; address: string }
  | { type: 'openkey:sign:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:signTypedData:request'; data: SignTypedDataRequest; sessionToken?: string }
  | { type: 'openkey:signTypedData:response'; success: true; signature: string; address: string }
  | { type: 'openkey:signTypedData:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:link-wallet:request' }
  | { type: 'openkey:link-wallet:response'; success: true; address: string; keyId: string }
  | { type: 'openkey:link-wallet:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:link-wallet:delegate' }
  | { type: 'openkey:link-wallet:result'; success: true; address: string; keyId: string }
  | { type: 'openkey:link-wallet:result'; success: false; error: OpenKeyError }
  | { type: 'openkey:auth:use-external-wallet' }
  | { type: 'openkey:resize'; height: number }
  | { type: 'openkey:ready' }
  | { type: 'openkey:close' };

const DEFAULT_HOST = 'https://openkey.so';
const POPUP_WIDTH = 400;
const POPUP_HEIGHT = 600;
const DEFAULT_TIMEOUT = 5 * 60 * 1000; // 5 minutes
const IFRAME_READY_TIMEOUT = 3000; // 3 seconds
const OAUTH_STORAGE_KEY = 'openkey_oauth';

class IframeModal {
  private root: HTMLDivElement;
  private shadow: ShadowRoot;
  private iframe: HTMLIFrameElement;
  private onClose: () => void;
  private onMessage: (data: MessageType) => void;
  private messageHandler: (event: MessageEvent) => void;
  private host: string;

  constructor(opts: { url: string; host: string; onClose: () => void; onMessage: (data: MessageType) => void }) {
    this.host = opts.host;
    this.onClose = opts.onClose;
    this.onMessage = opts.onMessage;

    const isMobile = window.matchMedia('(max-width: 639px)').matches;

    this.root = document.createElement('div');
    this.shadow = this.root.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      :host{all:initial}
      .ok-backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.4);backdrop-filter:blur(4px);z-index:999999;display:flex;align-items:${isMobile ? 'flex-end' : 'center'};justify-content:center;animation:ok-fade-in 150ms ease-out}
      .ok-card{position:relative;background:#fafafa;width:${isMobile ? '100%' : '400px'};border-radius:${isMobile ? '16px 16px 0 0' : '16px'};box-shadow:0 25px 50px -12px rgba(0,0,0,0.25);overflow:hidden;overflow-y:auto;animation:${isMobile ? 'ok-slide-up 250ms ease-out' : 'ok-scale-in 200ms ease-out'};max-height:90vh}
      .ok-close{position:absolute;top:8px;right:8px;width:24px;height:24px;border:none;background:transparent;color:#6b7280;font-size:18px;cursor:pointer;z-index:1;display:flex;align-items:center;justify-content:center;border-radius:4px}
      .ok-close:hover{color:#111827}
      .ok-handle{width:40px;height:4px;background:#d4d4d4;border-radius:2px;margin:8px auto 0}
      iframe{border:none;width:100%;height:400px;display:block;transition:height 200ms ease}
      .ok-backdrop.ok-exit{animation:ok-fade-out 150ms ease-in}
      .ok-backdrop.ok-exit .ok-card{animation:${isMobile ? 'ok-slide-down 200ms ease-in' : 'ok-scale-out 150ms ease-in'}}
      @keyframes ok-fade-in{from{opacity:0}to{opacity:1}}
      @keyframes ok-fade-out{from{opacity:1}to{opacity:0}}
      @keyframes ok-scale-in{from{opacity:0;transform:scale(0.95)}to{opacity:1;transform:scale(1)}}
      @keyframes ok-scale-out{from{opacity:1;transform:scale(1)}to{opacity:0;transform:scale(0.95)}}
      @keyframes ok-slide-up{from{transform:translateY(100%)}to{transform:translateY(0)}}
      @keyframes ok-slide-down{from{transform:translateY(0)}to{transform:translateY(100%)}}
    `;

    const backdrop = document.createElement('div');
    backdrop.className = 'ok-backdrop';
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) this.close();
    });

    const card = document.createElement('div');
    card.className = 'ok-card';

    if (isMobile) {
      const handle = document.createElement('div');
      handle.className = 'ok-handle';
      card.appendChild(handle);
    }

    const closeBtn = document.createElement('button');
    closeBtn.className = 'ok-close';
    closeBtn.textContent = '\u00d7';
    closeBtn.addEventListener('click', () => this.close());
    card.appendChild(closeBtn);

    this.iframe = document.createElement('iframe');
    this.iframe.src = opts.url;
    this.iframe.setAttribute('allow', 'publickey-credentials-get *; publickey-credentials-create *');
    this.iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms allow-popups');
    card.appendChild(this.iframe);

    backdrop.appendChild(card);
    this.shadow.appendChild(style);
    this.shadow.appendChild(backdrop);

    this.messageHandler = (event: MessageEvent) => {
      if (event.origin !== this.host) return;
      if (event.source !== this.iframe.contentWindow) return;
      const data = event.data as MessageType;
      if (data.type === 'openkey:resize') {
        const h = Math.min(data.height, Math.floor(window.innerHeight * 0.85));
        this.iframe.style.height = `${h}px`;
        return;
      }
      this.onMessage(data);
    };
    window.addEventListener('message', this.messageHandler);
    document.body.appendChild(this.root);
  }

  postMessage(message: object) {
    this.iframe.contentWindow?.postMessage(message, this.host);
  }

  destroy() {
    window.removeEventListener('message', this.messageHandler);
    this.root.remove();
  }

  private close() {
    const backdrop = this.shadow.querySelector('.ok-backdrop');
    if (backdrop) {
      backdrop.classList.add('ok-exit');
      setTimeout(() => {
        this.destroy();
        this.onClose();
      }, 200);
    } else {
      this.destroy();
      this.onClose();
    }
  }
}

class WalletPicker {
  private root: HTMLDivElement;
  private shadow: ShadowRoot;

  constructor(opts: { providers: EIP6963ProviderDetail[]; onSelect: (provider: EIP1193Provider) => void; onCancel: () => void }) {
    this.root = document.createElement('div');
    this.shadow = this.root.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      :host{all:initial}
      .wp-backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.4);backdrop-filter:blur(4px);z-index:1000000;display:flex;align-items:center;justify-content:center;animation:wp-fade 150ms ease-out}
      .wp-card{background:#fff;width:340px;border-radius:16px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.25);padding:20px;animation:wp-scale 200ms ease-out}
      .wp-title{font:600 16px/1.3 system-ui,sans-serif;color:#111;margin:0 0 12px}
      .wp-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px}
      .wp-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid #e5e7eb;border-radius:10px;background:transparent;cursor:pointer;font:14px/1.3 system-ui,sans-serif;color:#111;width:100%;text-align:left;transition:border-color 150ms}
      .wp-item:hover{border-color:#6366f1}
      .wp-icon{width:28px;height:28px;border-radius:6px}
      .wp-empty{font:14px/1.4 system-ui,sans-serif;color:#6b7280;text-align:center;padding:16px 0}
      .wp-cancel{display:block;width:100%;margin-top:12px;padding:8px;border:none;background:transparent;color:#6b7280;font:14px/1.3 system-ui,sans-serif;cursor:pointer;border-radius:8px}
      .wp-cancel:hover{background:#f3f4f6;color:#111}
      @keyframes wp-fade{from{opacity:0}to{opacity:1}}
      @keyframes wp-scale{from{opacity:0;transform:scale(0.95)}to{opacity:1;transform:scale(1)}}
      @media(prefers-color-scheme:dark){
        .wp-card{background:#1a1a1a;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5)}
        .wp-title{color:#f3f4f6}
        .wp-item{border-color:#374151;color:#f3f4f6}
        .wp-item:hover{border-color:#818cf8}
        .wp-empty{color:#9ca3af}
        .wp-cancel{color:#9ca3af}
        .wp-cancel:hover{background:#262626;color:#f3f4f6}
      }
    `;

    const backdrop = document.createElement('div');
    backdrop.className = 'wp-backdrop';
    backdrop.addEventListener('click', (e) => { if (e.target === backdrop) { this.destroy(); opts.onCancel(); } });

    const card = document.createElement('div');
    card.className = 'wp-card';

    const title = document.createElement('h2');
    title.className = 'wp-title';
    title.textContent = 'Select a wallet';
    card.appendChild(title);

    if (opts.providers.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'wp-empty';
      empty.textContent = 'No wallets detected';
      card.appendChild(empty);
    } else {
      const list = document.createElement('ul');
      list.className = 'wp-list';
      for (const { info, provider } of opts.providers) {
        const item = document.createElement('button');
        item.className = 'wp-item';
        if (info.icon) {
          const icon = document.createElement('img');
          icon.className = 'wp-icon';
          icon.src = info.icon;
          icon.alt = info.name;
          item.appendChild(icon);
        }
        const name = document.createElement('span');
        name.textContent = info.name;
        item.appendChild(name);
        item.addEventListener('click', () => { this.destroy(); opts.onSelect(provider); });
        list.appendChild(item);
      }
      card.appendChild(list);
    }

    const cancel = document.createElement('button');
    cancel.className = 'wp-cancel';
    cancel.textContent = 'Cancel';
    cancel.addEventListener('click', () => { this.destroy(); opts.onCancel(); });
    card.appendChild(cancel);

    backdrop.appendChild(card);
    this.shadow.appendChild(style);
    this.shadow.appendChild(backdrop);
    document.body.appendChild(this.root);
  }

  destroy() {
    this.root.remove();
  }
}

function showToast(message = 'Opening in new window\u2026', variant: 'info' | 'error' = 'info') {
  const bg = variant === 'error' ? '#dc2626' : '#1f2937';
  const root = document.createElement('div');
  const shadow = root.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `<style>:host{all:initial}.ok-toast{position:fixed;top:16px;right:16px;z-index:1000000;background:${bg};color:#f9fafb;padding:10px 16px;border-radius:8px;font:14px/1.4 system-ui,sans-serif;box-shadow:0 4px 12px rgba(0,0,0,0.15);animation:ok-t-in 200ms ease-out;max-width:360px}@keyframes ok-t-in{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}</style><div class="ok-toast">${message}</div>`;
  document.body.appendChild(root);
  setTimeout(() => root.remove(), 4000);
}

class ExternalWalletError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExternalWalletError';
  }
}

export class OpenKey {
  private host: string;
  private oauthHost: string;
  private appName: string;
  private mode: OpenKeyMode;
  private config: OpenKeyConfig;
  private popup: Window | null = null;
  private lastAuth: AuthResult | null = null;
  private discoveredProviders: EIP6963ProviderDetail[] = [];
  private sessionToken: string | null = null;

  constructor(config: OpenKeyConfig = {}) {
    this.config = config;
    this.host = config.host || DEFAULT_HOST;
    this.oauthHost = config.oauthHost || this.deriveOAuthHost(this.host);
    this.appName = config.appName || window.location.hostname;
    this.mode = config.mode ?? 'iframe';

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
   * Derive the OAuth API host from the main host by prefixing 'api.'
   * @param host - The main host URL
   * @returns The derived OAuth API host URL
   */
  private deriveOAuthHost(host: string): string {
    try {
      const url = new URL(host);
      if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
        return host.replace(/\/$/, '');
      }
      url.hostname = 'api.' + url.hostname;
      return url.toString().replace(/\/$/, '');
    } catch {
      return 'https://api.openkey.so';
    }
  }

  /**
   * Connect to OpenKey and get user's wallet address
   * Opens auth flow for user to select/create a key
   */
  async connect(opts?: { mode?: OpenKeyMode }): Promise<AuthResult> {
    const result = await this.openFlow<AuthResult>('connect', {
      type: 'openkey:auth:request',
      appName: this.appName,
    }, opts?.mode);
    this.lastAuth = result;
    return result;
  }

  /**
   * Link an external wallet to the user's OpenKey account
   * Opens link-wallet widget flow
   */
  async linkWallet(opts?: { mode?: OpenKeyMode }): Promise<{ address: string; keyId: string }> {
    return this.openFlow<{ address: string; keyId: string }>('link-wallet', {
      type: 'openkey:link-wallet:request',
    }, opts?.mode);
  }

  /**
   * Sign a message with the user's OpenKey wallet
   * For external keys, routes directly to the user's wallet provider
   */
  async signMessage(request: SignMessageRequest, opts?: { mode?: OpenKeyMode }): Promise<SignResult> {
    if (this.lastAuth?.keyType === 'EXTERNAL') {
      return this.signWithExternalWallet(request);
    }
    return this.signWithOpenKey(request, opts?.mode);
  }

  /**
   * Sign typed data (EIP-712) with the user's OpenKey wallet
   * For external keys, routes directly to the user's wallet provider
   */
  async signTypedData(request: SignTypedDataRequest, opts?: { mode?: OpenKeyMode }): Promise<SignResult> {
    if (this.lastAuth?.keyType === 'EXTERNAL') {
      return this.signTypedDataWithExternalWallet(request);
    }
    return this.signTypedDataWithOpenKey(request, opts?.mode);
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

    // 2. Check EIP-6963 discovered wallets silently (no popup)
    for (const { provider } of this.discoveredProviders) {
      try {
        const accounts = await provider.request({ method: 'eth_accounts' }) as string[];
        if (accounts.some(a => a.toLowerCase() === targetAddress.toLowerCase())) {
          return provider;
        }
      } catch {}
    }

    // 3. Fall back to window.ethereum silently
    if (typeof window !== 'undefined' && (window as any).ethereum) {
      const provider = (window as any).ethereum as EIP1193Provider;
      try {
        const accounts = await provider.request({ method: 'eth_accounts' }) as string[];
        if (accounts.some(a => a.toLowerCase() === targetAddress.toLowerCase())) {
          return provider;
        }
      } catch {}
    }

    throw new ExternalWalletError('External wallet not found. Connect the wallet that owns this key and try again.');
  }

  private async signWithExternalWallet(request: SignMessageRequest): Promise<SignResult> {
    let provider: EIP1193Provider;
    try {
      provider = await this.findWalletProvider(this.lastAuth!.address);
    } catch (e) {
      showToast((e as Error).message, 'error');
      throw e;
    }
    try {
      const hexMessage = this.toHex(request.message);
      const signature = await provider.request({
        method: 'personal_sign',
        params: [hexMessage, this.lastAuth!.address],
      });
      return { signature: signature as string, address: this.lastAuth!.address };
    } catch (e: any) {
      const msg = e?.message?.includes('not been authorized')
        ? 'Wallet rejected the request. Approve the connection in your wallet and try again.'
        : e?.message || 'Signing failed';
      showToast(msg, 'error');
      throw new Error(msg);
    }
  }

  private async signTypedDataWithExternalWallet(request: SignTypedDataRequest): Promise<SignResult> {
    let provider: EIP1193Provider;
    try {
      provider = await this.findWalletProvider(this.lastAuth!.address);
    } catch (e) {
      showToast((e as Error).message, 'error');
      throw e;
    }
    try {
      const signature = await provider.request({
        method: 'eth_signTypedData_v4',
        params: [this.lastAuth!.address, JSON.stringify(request)],
      });
      return { signature: signature as string, address: this.lastAuth!.address };
    } catch (e: any) {
      const msg = e?.message?.includes('not been authorized')
        ? 'Wallet rejected the request. Approve the connection in your wallet and try again.'
        : e?.message || 'Signing failed';
      showToast(msg, 'error');
      throw new Error(msg);
    }
  }

  private signWithOpenKey(request: SignMessageRequest, mode?: OpenKeyMode): Promise<SignResult> {
    return this.openFlow<SignResult>('sign', {
      type: 'openkey:sign:request',
      message: request.message,
      keyId: request.keyId,
      sessionToken: this.sessionToken || undefined,
    }, mode);
  }

  private signTypedDataWithOpenKey(request: SignTypedDataRequest, mode?: OpenKeyMode): Promise<SignResult> {
    return this.openFlow<SignResult>('sign-typed-data', {
      type: 'openkey:signTypedData:request',
      data: request,
      sessionToken: this.sessionToken || undefined,
    }, mode);
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
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const state = config.state || generateState();

      // Store for later token exchange
      sessionStorage.setItem(
        OAUTH_STORAGE_KEY,
        JSON.stringify({ verifier, state })
      );

      // Build authorization URL
      const authUrl = buildAuthorizationUrl({
        host: this.oauthHost,
        clientId: config.clientId,
        redirectUri: config.redirectUri,
        codeChallenge: challenge,
        state,
        scopes: ['openid'],
      });

      return this.openOAuthFlow(authUrl, state, config.redirectUri);
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

      const response = await fetch(`${this.oauthHost}/api/auth/oauth2/token`, {
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
      if (this.mode !== 'redirect') {
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
      showToast('Popup was blocked. Please allow popups for this site.', 'error');
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

  private resolveMode(override?: OpenKeyMode): OpenKeyMode {
    return override ?? this.mode;
  }

  private hasDetectedEoa(): boolean {
    if (this.discoveredProviders.length > 0) return true;
    if (typeof window !== 'undefined' && (window as any).ethereum) return true;
    return false;
  }

  private async openFlow<T>(action: string, message: object, modeOverride?: OpenKeyMode): Promise<T> {
    const mode = this.resolveMode(modeOverride);
    const origin = encodeURIComponent(window.location.origin);
    const eoaFlag = action === 'connect' && this.hasDetectedEoa() ? '&hasEoa=true' : '';

    if (mode === 'popup') {
      const url = `${this.host}/widget/${action}?origin=${origin}${eoaFlag}`;
      return new Promise((resolve, reject) => this.openPopup(url, message, resolve, reject));
    }

    if (mode === 'redirect') {
      const url = `${this.host}/widget/${action}?origin=${origin}${eoaFlag}`;
      window.location.href = url;
      return new Promise(() => {}); // never resolves, page navigates
    }

    // iframe mode with auto-fallback
    const url = `${this.host}/widget/embed/${action}?origin=${origin}${eoaFlag}`;
    return this.openIframeModal<T>(url, action, message, origin);
  }

  private openIframeModal<T>(url: string, action: string, message: object, origin: string): Promise<T> {
    return new Promise((resolve, reject) => {
      let readyReceived = false;
      let settled = false;
      let modal: IframeModal | null = null;

      const settle = (fn: () => void) => {
        if (settled) return;
        settled = true;
        fn();
      };

      const cleanup = () => {
        clearTimeout(readyTimeout);
        clearTimeout(overallTimeout);
        modal?.destroy();
        modal = null;
      };

      modal = new IframeModal({
        url,
        host: this.host,
        onClose: () => {
          settle(() => {
            clearTimeout(readyTimeout);
            clearTimeout(overallTimeout);
            modal = null;
            reject({ code: 'USER_CANCELLED', message: 'User cancelled the request' } as OpenKeyError);
          });
        },
        onMessage: (data: MessageType) => {
          if (data.type === 'openkey:ready') {
            readyReceived = true;
            modal?.postMessage(message);
            return;
          }

          if (data.type === 'openkey:close') {
            settle(() => {
              cleanup();
              reject({ code: 'USER_CANCELLED', message: 'User cancelled the request' } as OpenKeyError);
            });
            return;
          }

          if (data.type === 'openkey:link-wallet:delegate') {
            this.handleWalletLinkDelegation(modal!);
            return;
          }

          if (data.type === 'openkey:auth:use-external-wallet') {
            cleanup();
            this.handleExternalWalletConnect<T>(resolve, reject);
            return;
          }

          if (
            data.type === 'openkey:auth:response' ||
            data.type === 'openkey:sign:response' ||
            data.type === 'openkey:signTypedData:response' ||
            data.type === 'openkey:link-wallet:response'
          ) {
            settle(() => {
              cleanup();
              if (data.success) {
                if (data.type === 'openkey:auth:response') {
                  if (data.sessionToken) this.sessionToken = data.sessionToken;
                  resolve({ address: data.address, keyId: data.keyId, keyType: data.keyType || 'MANAGED' } as T);
                } else if (data.type === 'openkey:link-wallet:response') {
                  resolve({ address: data.address, keyId: data.keyId } as T);
                } else {
                  resolve({ signature: data.signature, address: data.address } as T);
                }
              } else {
                reject(data.error);
              }
            });
          }
        },
      });

      // Auto-fallback: if no openkey:ready within 3s, fall back to popup
      const readyTimeout = setTimeout(() => {
        if (readyReceived || settled) return;
        cleanup();
        console.warn('OpenKey: iframe blocked by CSP, falling back to popup. Add frame-src https://openkey.so to your CSP.');
        showToast();
        const popupUrl = `${this.host}/widget/${action}?origin=${origin}`;
        this.openPopup(popupUrl, message, (val: any) => settle(() => resolve(val)), (err: any) => settle(() => reject(err)));
      }, IFRAME_READY_TIMEOUT);

      // Overall 5-minute timeout
      const overallTimeout = setTimeout(() => {
        settle(() => {
          cleanup();
          reject({ code: 'TIMEOUT', message: 'Request timed out' } as OpenKeyError);
        });
      }, DEFAULT_TIMEOUT);
    });
  }

  private handleWalletLinkDelegation(modal: IframeModal) {
    const sendResult = (result: MessageType) => modal.postMessage(result);

    new WalletPicker({
      providers: this.discoveredProviders,
      onCancel: () => {
        sendResult({ type: 'openkey:link-wallet:result', success: false, error: { code: 'USER_CANCELLED', message: 'Wallet linking cancelled' } });
      },
      onSelect: async (provider) => {
        try {
          const accounts = await provider.request({ method: 'eth_requestAccounts' }) as string[];
          const address = accounts[0];
          if (!address) throw new Error('No account returned');

          // Get challenge from API
          const challengeRes = await fetch(`${this.host}/api/keys/link/challenge`, {
            method: 'POST',
            credentials: 'include',
          });
          if (!challengeRes.ok) throw new Error('Failed to get challenge');
          const { message } = await challengeRes.json();

          // Sign challenge with wallet
          const hexMessage = this.toHex(message);
          const signature = await provider.request({
            method: 'personal_sign',
            params: [hexMessage, address],
          }) as string;

          // Submit to API
          const linkRes = await fetch(`${this.host}/api/keys/link`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ address, signature, message }),
          });
          if (!linkRes.ok) {
            const err = await linkRes.json();
            throw new Error(err.error || 'Failed to link wallet');
          }
          const { key } = await linkRes.json();

          sendResult({ type: 'openkey:link-wallet:result', success: true, address: key.address, keyId: key.id });
        } catch (e: any) {
          sendResult({ type: 'openkey:link-wallet:result', success: false, error: { code: 'UNKNOWN', message: e.message || 'Wallet linking failed' } });
        }
      },
    });
  }

  private handleExternalWalletConnect<T>(
    resolve: (value: T) => void,
    reject: (error: OpenKeyError) => void
  ) {
    new WalletPicker({
      providers: this.discoveredProviders,
      onCancel: () => {
        reject({ code: 'USER_CANCELLED', message: 'User cancelled wallet selection' });
      },
      onSelect: async (provider) => {
        try {
          const accounts = await provider.request({ method: 'eth_requestAccounts' }) as string[];
          const address = accounts[0];
          if (!address) throw new Error('No account returned');
          const result = { address, keyId: `external:${address}`, keyType: 'EXTERNAL' as const };
          this.lastAuth = result;
          resolve(result as T);
        } catch (e: any) {
          reject({ code: 'UNKNOWN', message: e.message || 'Failed to connect wallet' });
        }
      },
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
      showToast('Popup was blocked. Please allow popups for this site.', 'error');
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
      if (event.source !== this.popup) return;

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

      if (data.type === 'openkey:auth:use-external-wallet') {
        cleanup();
        this.popup?.close();
        this.handleExternalWalletConnect<T>(resolve, reject);
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
            if (data.sessionToken) this.sessionToken = data.sessionToken;
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
  }
}

/**
 * EIP-1193 compatible provider that wraps an OpenKey instance.
 * Transparently routes signing to either OpenKey (managed keys) or the user's
 * wallet (external keys).
 */
export class OpenKeyProvider implements EIP1193Provider {
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
          try {
            const provider = await this.openkey.findWalletProvider(this.address);
            return await provider.request({ method, params });
          } catch (e: any) {
            showToast(e?.message || 'External wallet signing failed', 'error');
            throw e;
          }
        }
        // Managed key: route through OpenKey
        const message = this.hexToString(params![0] as string);
        const result = await this.openkey.signMessage({ message, keyId: this.keyId });
        return result.signature;
      }

      case 'eth_signTypedData_v4': {
        if (this.keyType === 'EXTERNAL') {
          try {
            const provider = await this.openkey.findWalletProvider(this.address);
            return await provider.request({ method, params });
          } catch (e: any) {
            showToast(e?.message || 'External wallet signing failed', 'error');
            throw e;
          }
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

/**
 * @deprecated Use `OpenKeyProvider` instead. Will be removed in a future version.
 */
export const OpenKeyEIP1193Provider = OpenKeyProvider;

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
