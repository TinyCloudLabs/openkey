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

// ======= Versioned TinyCloud authorization protocol =======
//
// This protocol replaces the legacy `signMessage()` path for TinyCloud
// SIWE-ReCap requests. It preserves the legacy exact-byte behavior for
// existing callers: `signMessage()` continues to sign the caller's exact
// bytes and OpenKey NEVER rewrites them. Callers who want to let the user
// narrow the requested capabilities call `authorizeTinyCloud()` instead.
//
// The response carries `signedMessage` — the exact bytes the signature
// verifies against. TinyCloud completes the session with these bytes, not
// the caller's original request. See `NodeUserAuthorization` in the
// js-sdk for the consumer side of this contract.

export interface TinyCloudAuthorizationRequestV1 {
  protocolVersion: 1;
  /** Suggested SIWE (may be edited server-side before signing). */
  siwe: string;
  /** The keyId the user picked, if the caller has one in mind. */
  keyId?: string;
  /**
   * The session-key JWK bound to `siwe`. Required so the server can
   * regenerate a narrowed SIWE tied to the SAME session key when the
   * user removes capabilities. Passing a mismatched jwk (or omitting it
   * when the widget attempts to narrow) causes the /authorize-sign call
   * to fail — never a silent fallback to the caller's exact bytes.
   */
  jwk?: Record<string, unknown>;
  /**
   * The TinyCloud host the resulting session will activate against.
   * Bound into the /authorize-sign-prepare context so /authorize-sign
   * cannot swap hosts server-side. Optional for callers that do not
   * plan to activate a delegation (they should still forward it when
   * known; the empty string is treated as "unknown").
   */
  host?: string;
  /** Optional presentation envelope (name, reason, manifest). */
  presentation?: CapabilityPresentationEnvelopeV1;
}

export interface TinyCloudAuthorizationResultV1 {
  protocolVersion: 1;
  /** EIP-55 signer address. */
  address: string;
  /** Signature over `signedMessage`. */
  signature: string;
  /** The EXACT bytes the signature verifies against. Never the caller's original. */
  signedMessage: string;
  /** The action IDs the user (or default consent) selected. */
  selectedActionKeys: string[];
  /** Effective grant set after any narrowing. */
  permissions: Array<{
    service: string;
    space: string;
    path: string;
    actions: string[];
  }>;
}

export interface CapabilityPresentationEnvelopeV1 {
  protocolVersion: 1;
  /** Human-readable requester name shown in the review. */
  displayName?: string;
  /** Reason string the requester supplied for the delegation. */
  reason?: string;
  /** Manifest ID + digest, when the app publishes a signed manifest. */
  manifestId?: string;
  manifestDigest?: string;
}

export type ManagedAccountState = 'PROVISIONED' | 'MANAGED' | 'DISABLED' | 'EJECTING' | 'USER_OWNED' | 'EXPIRED' | 'FAILED';

export interface ManagedAccountSummary {
  id: string;
  subjectEmail: string;
  externalUserId: string | null;
  email: string;
  address: string;
  state: ManagedAccountState;
  custodyEpoch: number;
  tenantAccess: 'NOT_REQUIRED' | 'PENDING' | 'REVOKED';
  createdAt: string;
  updatedAt: string;
}

export type CredentialRotationResponse = {
  credential: {
    id: string;
    name: string;
    kind: 'MANAGEMENT';
    secretPrefix: string;
    subjectUserId: string | null;
    createdAt: string;
    lastUsedAt: string | null;
    revokedAt: string | null;
  };
  secret: string;
} | {
  alreadyRotated: true;
  credentialId: string | null;
  message: string;
};

export interface OrganizationEntitlements {
  plan: 'FREE' | 'PRO' | 'ENTERPRISE';
  version: number;
  maxApps: number;
  maxOrganizationMembers: number;
  maxManagedAccounts: number;
  monthlyActiveManagedUsers: number;
  storageBytesPerManagedAccount: string;
  requestsPerMinute: number;
  maxTenantDelegationTtlSeconds: number;
  maxTenantPolicyVersion: number;
  webhookDelivery: boolean;
  maxWebhookEndpoints: number;
  auditRetentionDays: number;
}

export type OpenKeyLifecycleEvent =
  | 'managed_account.created'
  | 'managed_account.provisioning_failed'
  | 'custody.transfer_started'
  | 'custody.transferred'
  | 'tenant_access.revocation_pending'
  | 'tenant_access.revoked'
  | 'managed_account.quota_changed';

// Sol MAJOR-3: transport messages must carry `requestId` and
// `protocolVersion` for the SDK to correlate concurrent flows. Legacy
// (unversioned) messages are allowed for backward compatibility with
// the plain signMessage path, but versioned flows (authorizeTinyCloud)
// always carry both fields and the SDK matches them on response.
type MessageType =
  | { type: 'openkey:auth:request'; appName: string }
  | { type: 'openkey:auth:response'; success: true; address: string; keyId: string; keyType?: 'MANAGED' | 'EXTERNAL'; sessionToken?: string; requestId?: string; protocolVersion?: number }
  | { type: 'openkey:auth:response'; success: false; error: OpenKeyError; requestId?: string; protocolVersion?: number }
  | { type: 'openkey:sign:request'; message: string; keyId?: string; sessionToken?: string; requestId?: string; protocolVersion?: number }
  | { type: 'openkey:sign:response'; success: true; signature: string; address: string; requestId?: string; protocolVersion?: number }
  | {
      type: 'openkey:sign:response';
      success: true;
      signature: string;
      address: string;
      /** Versioned: exact bytes the signature verifies against. */
      signedMessage?: string;
      /** Versioned: action IDs selected by the user. */
      selectedActionKeys?: string[];
      /** Versioned: effective grants after narrowing. */
      permissions?: Array<{
        service: string;
        space: string;
        path: string;
        actions: string[];
      }>;
      requestId?: string;
      protocolVersion?: number;
    }
  | { type: 'openkey:sign:response'; success: false; error: OpenKeyError; requestId?: string; protocolVersion?: number }
  // Sol MAJOR-3 (continuation): external-key review flow. The widget
  // renders the shared SigningApproval UI, calls /authorize-sign-prepare
  // and /authorize-sign-preview on the user's behalf, and — instead of
  // signing server-side with a managed key — hands the SDK back the
  // preview data so the SDK can invoke the user's wallet. The SDK then
  // completes /authorize-sign with the resulting `externalSignature`.
  | {
      type: 'openkey:externalSign:approve';
      success: true;
      requestId: string;
      protocolVersion: number;
      authorizationContextToken: string;
      previewApprovalToken: string;
      signedMessage: string;
      selectedActionIds: string[];
      address: string;
    }
  | {
      type: 'openkey:externalSign:approve';
      success: false;
      requestId: string;
      protocolVersion: number;
      error: OpenKeyError;
    }
  | { type: 'openkey:signTypedData:request'; data: SignTypedDataRequest; sessionToken?: string; requestId?: string; protocolVersion?: number }
  | { type: 'openkey:signTypedData:response'; success: true; signature: string; address: string; requestId?: string; protocolVersion?: number }
  | { type: 'openkey:signTypedData:response'; success: false; error: OpenKeyError; requestId?: string; protocolVersion?: number }
  | { type: 'openkey:link-wallet:request' }
  | { type: 'openkey:link-wallet:response'; success: true; address: string; keyId: string }
  | { type: 'openkey:link-wallet:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:link-wallet:delegate' }
  | { type: 'openkey:link-wallet:result'; success: true; address: string; keyId: string }
  | { type: 'openkey:link-wallet:result'; success: false; error: OpenKeyError }
  | { type: 'openkey:auth:use-external-wallet' }
  | { type: 'openkey:resize'; height: number; protocolVersion?: number }
  | { type: 'openkey:ready'; protocolVersion?: number }
  | { type: 'openkey:close' };

const DEFAULT_HOST = 'https://openkey.so';
const POPUP_WIDTH = 400;
const POPUP_HEIGHT = 600;
const DEFAULT_TIMEOUT = 5 * 60 * 1000; // 5 minutes
const IFRAME_READY_TIMEOUT = 3000; // 3 seconds
const OAUTH_STORAGE_KEY = 'openkey_oauth';

/**
 * Sol final continuation contract requirement 5: pure validation of an
 * incoming iframe resize message envelope. Exported so unit tests can
 * exercise every rejection branch — wrong requestId, wrong version, no
 * active request, malformed height — without booting the browser
 * runtime that `IframeModal` requires.
 *
 * Returns the sanitized height when acceptable, or `null` when the
 * message must be dropped.
 */
export function validateIframeResize(
  incoming: unknown,
  expected: {
    requestId: string | null;
    protocolVersion: number | null;
    viewportHeight: number;
  },
): number | null {
  if (!incoming || typeof incoming !== 'object') return null;
  const data = incoming as Record<string, unknown>;
  if (data.type !== 'openkey:resize') return null;
  if (expected.requestId === null || expected.protocolVersion === null) return null;
  if (typeof data.protocolVersion !== 'number' || data.protocolVersion !== expected.protocolVersion) {
    return null;
  }
  if (typeof data.requestId !== 'string' || data.requestId !== expected.requestId) {
    return null;
  }
  if (typeof data.height !== 'number' || !Number.isFinite(data.height) || data.height <= 0) {
    return null;
  }
  return Math.min(data.height, Math.floor(expected.viewportHeight * 0.85));
}

class IframeModal {
  private root: HTMLDivElement;
  private shadow: ShadowRoot;
  private iframe: HTMLIFrameElement;
  private onClose: () => void;
  private onMessage: (data: MessageType) => void;
  private messageHandler: (event: MessageEvent) => void;
  private host: string;
  // Sol final continuation contract requirement 5: iframe resize traffic
  // MUST correlate to the active request's requestId AND protocolVersion.
  // Set by `setExpectedCorrelation` after the outer flow decides which
  // request this modal is bound to. When both are null, resize messages
  // are dropped (no active request → no resize authority).
  private expectedRequestId: string | null = null;
  private expectedProtocolVersion: number | null = null;

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
      .ok-backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.42);z-index:999999;display:flex;align-items:${isMobile ? 'flex-end' : 'center'};justify-content:center;animation:ok-fade-in 150ms ease-out}
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
    this.iframe.setAttribute('allow', 'clipboard-write *; publickey-credentials-get *; publickey-credentials-create *');
    this.iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox');
    card.appendChild(this.iframe);

    backdrop.appendChild(card);
    this.shadow.appendChild(style);
    this.shadow.appendChild(backdrop);

    this.messageHandler = (event: MessageEvent) => {
      if (event.origin !== this.host) return;
      if (event.source !== this.iframe.contentWindow) return;
      const data = event.data as MessageType;
      if (data.type === 'openkey:resize') {
        // Sol final continuation contract requirement 5: resize MUST
        // carry the EXACT active requestId AND protocolVersion. Every
        // rejection branch is covered by unit tests over
        // `validateIframeResize`.
        const h = validateIframeResize(event.data, {
          requestId: this.expectedRequestId,
          protocolVersion: this.expectedProtocolVersion,
          viewportHeight: window.innerHeight,
        });
        if (h === null) return;
        this.iframe.style.height = `${h}px`;
        return;
      }
      // Sol MAJOR-9: openkey:close MUST also carry versioning when the
      // request was versioned. The close message is the only other one
      // that a stray frame could try to inject to abort a legitimate
      // approval. For simplicity we drop unversioned close on messages
      // arriving from an authenticated iframe source and let the SDK's
      // timeout eventually fire.
      if (data.type === 'openkey:close') {
        // No protocol-version requirement enforced here because a
        // versionless close is a legitimate cancel from any widget
        // version; source+origin validation earlier is sufficient.
      }
      this.onMessage(data);
    };
    window.addEventListener('message', this.messageHandler);
    document.body.appendChild(this.root);
  }

  postMessage(message: object) {
    this.iframe.contentWindow?.postMessage(message, this.host);
  }

  /**
   * Sol final continuation contract requirement 5: bind the active
   * request correlation so subsequent resize (and future correlated)
   * messages can be verified against `requestId` + `protocolVersion`.
   *
   * The outer flow calls this immediately BEFORE posting the sign
   * request into the iframe, so a resize that arrives synchronously
   * after ready is correlated correctly. Passing `null` for either
   * argument disables correlation (resize is dropped).
   */
  setExpectedCorrelation(requestId: string | null, protocolVersion: number | null): void {
    this.expectedRequestId = requestId;
    this.expectedProtocolVersion = protocolVersion;
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
      .wp-backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.42);z-index:1000000;display:flex;align-items:center;justify-content:center;animation:wp-fade 150ms ease-out}
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
   * Better-auth session token relayed during connect(), or null if the
   * flow did not provide one. Use as a bearer token for API calls made
   * on the user's behalf (e.g. TinyCloud auto-sign bootstrap signing).
   */
  getSessionToken(): string | null {
    return this.sessionToken;
  }

  /**
   * Endpoint + bearer token for a TinyCloud auto-sign signing strategy.
   * The endpoint is on the OpenKey API host and only signs requests the
   * server-side bootstrap allowlist permits.
   */
  tinycloudSigningOptions(): { endpoint: string; token: string | null } {
    return {
      endpoint: `${this.oauthHost}/api/delegate/sign`,
      token: this.sessionToken,
    };
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
   * Versioned TinyCloud authorization protocol (v1).
   *
   * Unlike `signMessage()` (which is contractually byte-exact — the returned
   * signature always verifies against the caller's exact bytes), this method
   * permits the user to narrow the requested capabilities before signing.
   * OpenKey may therefore regenerate the SIWE. The response carries
   * `signedMessage` — the exact bytes the signature actually verifies against.
   *
   * TinyCloud completes the session with `signedMessage`, not the original
   * `siwe` passed in. Consumers MUST use the returned bytes and MUST NOT
   * assume the returned grants are a superset of what they requested — the
   * user is allowed to remove any grant that is not required.
   *
   * Legacy `signMessage()` callers are unaffected: their exact-byte contract
   * remains preserved and OpenKey never rewrites their bytes.
   */
  async authorizeTinyCloud(
    request: TinyCloudAuthorizationRequestV1,
    opts?: { mode?: OpenKeyMode },
  ): Promise<TinyCloudAuthorizationResultV1> {
    if (request.protocolVersion !== 1) {
      throw new Error(
        `authorizeTinyCloud only supports protocolVersion 1; got ${request.protocolVersion}`,
      );
    }
    if (typeof request.siwe !== 'string' || !request.siwe) {
      throw new Error('authorizeTinyCloud requires a non-empty SIWE');
    }
    // Sol MAJOR-3 (continuation): branch to the external-wallet preview→
    // sign→finalize flow when the target key is EXTERNAL. External keys
    // are held by the user's browser wallet — OpenKey does not have the
    // private material, so it cannot execute the managed-key path.
    //
    // Routing rules:
    //   1. If the caller passed request.keyId AND it references an
    //      EXTERNAL key (lastAuth.keyId matches AND lastAuth.keyType is
    //      EXTERNAL), route to external.
    //   2. If the caller did NOT pass request.keyId but the lastAuth key
    //      is EXTERNAL, route to external.
    //   3. Otherwise (managed key), route through the widget for
    //      server-side signing.
    //
    // The prior check `this.lastAuth?.keyType === 'EXTERNAL'` alone let
    // an explicit external keyId enter the managed widget path when
    // lastAuth was MANAGED, causing /authorize-sign to be called without
    // an externalSignature.
    const explicitKeyId = request.keyId;
    const explicitKeyIsExternal =
      explicitKeyId &&
      this.lastAuth?.keyId === explicitKeyId &&
      this.lastAuth?.keyType === 'EXTERNAL';
    const shouldRouteExternal =
      explicitKeyIsExternal ||
      (!explicitKeyId && this.lastAuth?.keyType === 'EXTERNAL');
    if (shouldRouteExternal) {
      return this.authorizeTinyCloudExternal(request, opts);
    }
    // Sol CRITICAL-1: Send a DISTINCT versioned sign request so the widget
    // knows to route through the server-authoritative /authorize-sign
    // endpoint. protocolVersion: 1 with the extended payload triggers the
    // server-authoritative narrowing path — the widget refuses to fall
    // back to legacy exact-byte signMessage() for a versioned request
    // whose origin is real.
    const requestId = `ok-auth-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    // Sol MAJOR-3: fall back to the connected key when the caller did not
    // pass an explicit keyId. Without this fallback the widget renders
    // 'Please connect first.' because it has no key context, and the
    // NodeUserAuthorization bridge never carries a keyId when the caller
    // only ran connect() — the widget path is otherwise unable to sign.
    const resolvedKeyId = request.keyId ?? this.lastAuth?.keyId;
    const raw = await this.openFlow<{
      signature: string;
      address: string;
      signedMessage?: string;
      selectedActionKeys?: string[];
      permissions?: TinyCloudAuthorizationResultV1['permissions'];
    }>(
      'sign',
      {
        type: 'openkey:sign:request',
        requestId,
        protocolVersion: 1,
        message: request.siwe,
        keyId: resolvedKeyId,
        // Forward JWK so the widget can pass it to /authorize-sign for
        // narrowed-SIWE regeneration.
        jwk: request.jwk,
        // Forward the TinyCloud host so the widget can bind it into the
        // /authorize-sign-prepare context (Sol MAJOR-2).
        host: request.host,
        sessionToken: this.sessionToken || undefined,
      },
      opts?.mode,
    );
    // Sol CRITICAL-1: NO silent fallback to `request.siwe`. If the widget
    // returned an authorization response without `signedMessage`, that is
    // a protocol violation and MUST fail — silently accepting the caller's
    // original bytes as `signedMessage` while selectedActionKeys/permissions
    // reflect a narrower set is exactly the bug this rewrite prevents.
    if (typeof raw.signedMessage !== 'string' || !raw.signedMessage) {
      throw new Error(
        'authorizeTinyCloud: widget returned no signedMessage — signature would not correspond to the displayed authorization',
      );
    }
    if (!Array.isArray(raw.selectedActionKeys)) {
      throw new Error(
        'authorizeTinyCloud: widget returned no selectedActionKeys — cannot verify displayed authorization matches the signed bytes',
      );
    }
    if (!Array.isArray(raw.permissions)) {
      throw new Error(
        'authorizeTinyCloud: widget returned no permissions — cannot verify displayed authorization matches the signed bytes',
      );
    }
    return {
      protocolVersion: 1,
      address: raw.address,
      signature: raw.signature,
      signedMessage: raw.signedMessage,
      selectedActionKeys: raw.selectedActionKeys,
      permissions: raw.permissions,
    };
  }

  /**
   * Sol MAJOR-3 (continuation): authorizeTinyCloud path for external keys.
   * The wallet lives outside OpenKey, so the SDK opens the shared widget
   * for review + preview, then invokes the user's wallet to sign the
   * preview bytes, then finalizes server-side via /authorize-sign.
   *
   * Flow:
   *   1. Open the widget with `externalSign: true` — the widget renders
   *      the shared SigningApproval UI, calls /authorize-sign-prepare,
   *      calls /authorize-sign-preview after the user approves a
   *      selection, and hands back `{ previewApprovalToken,
   *      signedMessage, selectedActionIds, address, authorizationContextToken }`.
   *   2. SDK invokes the user's wallet on the returned signedMessage.
   *   3. SDK POSTs /authorize-sign with `externalSignature`.
   *
   * Legacy exact-byte signMessage callers are unaffected — this path is
   * only taken via authorizeTinyCloud (protocolVersion:1) when the target
   * key is EXTERNAL. Sol's rejection required this path to go through
   * the same review UI as managed keys.
   */
  private async authorizeTinyCloudExternal(
    request: TinyCloudAuthorizationRequestV1,
    opts?: { mode?: OpenKeyMode },
  ): Promise<TinyCloudAuthorizationResultV1> {
    const keyId = request.keyId ?? this.lastAuth?.keyId;
    if (!keyId) {
      throw new Error(
        'authorizeTinyCloud (external) requires a keyId — call connect() first or pass request.keyId',
      );
    }
    const walletAddress = this.lastAuth?.address;
    if (!walletAddress) {
      throw new Error(
        'authorizeTinyCloud (external) requires a connected wallet — call connect() first',
      );
    }
    // Sol MAJOR-3 (continuation): open the shared widget UI so the user
    // sees and can narrow the review, identical to the managed-key flow.
    const requestId = `ok-ext-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const approval = await this.openFlow<{
      authorizationContextToken: string;
      previewApprovalToken: string;
      signedMessage: string;
      selectedActionIds: string[];
      address: string;
    }>(
      'sign',
      {
        type: 'openkey:sign:request',
        requestId,
        protocolVersion: 1,
        message: request.siwe,
        keyId,
        jwk: request.jwk,
        host: request.host,
        sessionToken: this.sessionToken || undefined,
        // Sol MAJOR-3 (continuation): tell the widget to hand us back
        // the previewApproval instead of asking OpenKey to sign
        // server-side with a managed key. The widget will still render
        // the SAME SigningApproval component; it just diverges at the
        // "sign" step and emits `openkey:externalSign:approve` back
        // through the transport.
        externalSign: true,
      } as unknown as MessageType,
      opts?.mode,
    );
    if (!approval?.previewApprovalToken || !approval?.signedMessage) {
      throw new Error(
        'authorizeTinyCloud (external): widget did not return a previewApprovalToken + signedMessage',
      );
    }
    if (
      approval.address &&
      approval.address.toLowerCase() !== walletAddress.toLowerCase()
    ) {
      throw new Error(
        `authorizeTinyCloud (external): widget preview address ${approval.address} does not match connected wallet ${walletAddress}`,
      );
    }
    // Wallet signs the exact bytes the widget previewed.
    const provider = await this.findWalletProvider(walletAddress);
    const hexMessage = this.toHex(approval.signedMessage);
    const walletSignature = (await provider.request({
      method: 'personal_sign',
      params: [hexMessage, walletAddress],
    })) as string;
    // Finalize — server verifies the wallet signature against the exact
    // same bytes it emitted for the preview.
    const finalizeRes = await fetch(
      `${this.oauthHost}/api/delegate/authorize-sign`,
      {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          authorizationContextToken: approval.authorizationContextToken,
          previewApprovalToken: approval.previewApprovalToken,
          selectedActionIds: approval.selectedActionIds,
          protocolVersion: 1,
          externalSignature: walletSignature,
        }),
      },
    );
    if (!finalizeRes.ok) {
      const body = await finalizeRes.json().catch(() => ({ error: `HTTP ${finalizeRes.status}` }));
      throw new Error(body.error || `authorize-sign failed (${finalizeRes.status})`);
    }
    const finalize = await finalizeRes.json();
    if (finalize.signedMessage !== approval.signedMessage) {
      throw new Error(
        'authorizeTinyCloud (external): server signed different bytes than the preview showed',
      );
    }
    return {
      protocolVersion: 1,
      address: finalize.address,
      signature: finalize.signature,
      signedMessage: finalize.signedMessage,
      selectedActionKeys: finalize.selectedActionKeys ?? [],
      permissions: finalize.permissions ?? [],
    };
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

  private providerCandidates(): EIP1193Provider[] {
    const providers: EIP1193Provider[] = [];
    if (this.config.externalProvider) {
      providers.push(this.config.externalProvider);
    }
    providers.push(...this.discoveredProviders.map(({ provider }) => provider));
    if (typeof window !== 'undefined' && (window as any).ethereum) {
      providers.push((window as any).ethereum as EIP1193Provider);
    }
    return [...new Set(providers)];
  }

  private async providerHasAccount(
    provider: EIP1193Provider,
    method: 'eth_accounts' | 'eth_requestAccounts',
    targetAddress: string
  ): Promise<boolean> {
    try {
      const accounts = await provider.request({ method }) as string[];
      return accounts.some((account) => account.toLowerCase() === targetAddress.toLowerCase());
    } catch {
      return false;
    }
  }

  /**
   * Find a wallet provider that controls the given address.
   * Checks connected accounts first, then asks the wallet to authorize the
   * app origin if the external key was linked elsewhere.
   */
  async findWalletProvider(targetAddress: string): Promise<EIP1193Provider> {
    const providers = this.providerCandidates();

    for (const provider of providers) {
      if (await this.providerHasAccount(provider, 'eth_accounts', targetAddress)) {
        return provider;
      }
    }

    for (const provider of providers) {
      if (await this.providerHasAccount(provider, 'eth_requestAccounts', targetAddress)) {
        return provider;
      }
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
    // Sol MAJOR-3: capture the outgoing request's correlation IDs so
    // response handlers can require them to match. Legacy unversioned
    // requests carry neither and skip correlation.
    const outgoingRequestId = (message as { requestId?: unknown }).requestId;
    const outgoingProtocolVersion = (message as { protocolVersion?: unknown }).protocolVersion;
    const isVersionedRequest =
      typeof outgoingRequestId === 'string' &&
      typeof outgoingProtocolVersion === 'number' &&
      outgoingProtocolVersion >= 1;
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
            // Sol final continuation contract requirement 5: bind the
            // correlation BEFORE posting the sign request so any resize
            // that races the request into the parent is validated
            // against the correct (requestId, protocolVersion) pair.
            if (isVersionedRequest && modal) {
              modal.setExpectedCorrelation(
                outgoingRequestId as string,
                outgoingProtocolVersion as number,
              );
            }
            modal?.postMessage(message);
            return;
          }
          // Sol MAJOR-3: correlate versioned responses. If the request
          // was versioned, drop any response that doesn't match the
          // outgoing requestId/protocolVersion. If the request was
          // unversioned (legacy), accept any response.
          if (isVersionedRequest) {
            const respRequestId = (data as { requestId?: unknown }).requestId;
            const respVersion = (data as { protocolVersion?: unknown }).protocolVersion;
            if (respRequestId !== outgoingRequestId) return;
            if (respVersion !== outgoingProtocolVersion) return;
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
            data.type === 'openkey:link-wallet:response' ||
            data.type === 'openkey:externalSign:approve'
          ) {
            settle(() => {
              cleanup();
              if (data.success) {
                if (data.type === 'openkey:auth:response') {
                  if (data.sessionToken) this.sessionToken = data.sessionToken;
                  resolve({ address: data.address, keyId: data.keyId, keyType: data.keyType || 'MANAGED' } as T);
                } else if (data.type === 'openkey:link-wallet:response') {
                  resolve({ address: data.address, keyId: data.keyId } as T);
                } else if (data.type === 'openkey:externalSign:approve') {
                  resolve({
                    authorizationContextToken: (data as any).authorizationContextToken,
                    previewApprovalToken: (data as any).previewApprovalToken,
                    signedMessage: (data as any).signedMessage,
                    selectedActionIds: (data as any).selectedActionIds,
                    address: (data as any).address,
                  } as T);
                } else {
                  resolve({
                    signature: (data as any).signature,
                    address: (data as any).address,
                    signedMessage: (data as any).signedMessage,
                    selectedActionKeys: (data as any).selectedActionKeys,
                    permissions: (data as any).permissions,
                  } as T);
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

    // Sol MAJOR-3: correlation IDs for versioned popups.
    const outgoingRequestId = (message as { requestId?: unknown }).requestId;
    const outgoingProtocolVersion = (message as { protocolVersion?: unknown }).protocolVersion;
    const isVersionedRequest =
      typeof outgoingRequestId === 'string' &&
      typeof outgoingProtocolVersion === 'number' &&
      outgoingProtocolVersion >= 1;
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
        // Sol MAJOR-4: correlate close messages to the current versioned
        // request. A same-origin, same-source stale close from a
        // previous /widget/sign window MUST NOT tear down the active
        // request. Unversioned close messages are only accepted on
        // unversioned flows (legacy signMessage callers).
        if (isVersionedRequest) {
          const closeRequestId = (data as { requestId?: unknown }).requestId;
          const closeVersion = (data as { protocolVersion?: unknown }).protocolVersion;
          if (closeRequestId !== outgoingRequestId) return;
          if (closeVersion !== outgoingProtocolVersion) return;
        }
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
        data.type === 'openkey:link-wallet:response' ||
        data.type === 'openkey:externalSign:approve'
      ) {
        // Sol MAJOR-3: drop cross-correlated responses on versioned flows.
        if (isVersionedRequest) {
          const respRequestId = (data as { requestId?: unknown }).requestId;
          const respVersion = (data as { protocolVersion?: unknown }).protocolVersion;
          if (respRequestId !== outgoingRequestId) return;
          if (respVersion !== outgoingProtocolVersion) return;
        }
        cleanup();
        this.popup?.close();

        if (data.success) {
          if (data.type === 'openkey:auth:response') {
            if (data.sessionToken) this.sessionToken = data.sessionToken;
            resolve({ address: data.address, keyId: data.keyId, keyType: data.keyType || 'MANAGED' } as T);
          } else if (data.type === 'openkey:link-wallet:response') {
            resolve({ address: data.address, keyId: data.keyId } as T);
          } else if (data.type === 'openkey:externalSign:approve') {
            // Sol MAJOR-3 (continuation): hand the preview payload back
            // to authorizeTinyCloudExternal so it can invoke the wallet.
            resolve({
              authorizationContextToken: (data as any).authorizationContextToken,
              previewApprovalToken: (data as any).previewApprovalToken,
              signedMessage: (data as any).signedMessage,
              selectedActionIds: (data as any).selectedActionIds,
              address: (data as any).address,
            } as T);
          } else {
            resolve({
              signature: (data as any).signature,
              address: (data as any).address,
              signedMessage: (data as any).signedMessage,
              selectedActionKeys: (data as any).selectedActionKeys,
              permissions: (data as any).permissions,
            } as T);
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
/** Server-side tenant client. Keep this credential on the tenant backend. */
export class OpenKeyManagementClient {
  private readonly apiBaseUrl: string;
  private readonly serverCredential: string;
  private readonly fetchImpl: typeof fetch;

  constructor(input: { apiBaseUrl?: string; serverCredential: string; fetch?: typeof fetch }) {
    this.apiBaseUrl = (input.apiBaseUrl ?? 'https://api.openkey.so').replace(/\/$/, '');
    this.serverCredential = input.serverCredential;
    this.fetchImpl = input.fetch ?? fetch;
  }

  async createAccount(
    request: { email: string; externalUserId?: string; metadata?: Record<string, unknown> },
    idempotencyKey: string,
  ): Promise<ManagedAccountSummary> {
    return this.request('/v1/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(request),
    });
  }

  async listAccounts(filters: { email?: string; externalUserId?: string; status?: 'active' | 'disabled' | 'user_owned' | 'history'; limit?: number; cursor?: string } = {}): Promise<{ accounts: ManagedAccountSummary[]; nextCursor: string | null }> {
    const params = new URLSearchParams();
    if (filters.email) params.set('email', filters.email);
    if (filters.externalUserId) params.set('externalUserId', filters.externalUserId);
    if (filters.status) params.set('status', filters.status);
    if (filters.limit) params.set('limit', String(filters.limit));
    if (filters.cursor) params.set('cursor', filters.cursor);
    const query = params.toString();
    return this.request(`/v1/accounts${query ? `?${query}` : ''}`);
  }

  async getAccount(id: string): Promise<ManagedAccountSummary> {
    return this.request(`/v1/accounts/${encodeURIComponent(id)}`);
  }

  async sign(
    id: string,
    request:
      | { message: string; format?: 'utf8' | 'hex' }
      | { typedData: SignTypedDataRequest }
      | { digest: `0x${string}`; auditContext: string }
      | { transaction: unknown },
    idempotencyKey: string,
    expectedCustodyEpoch: number,
  ): Promise<{ signature?: string; signedTransaction?: string; address: string }> {
    return this.request(`/v1/accounts/${encodeURIComponent(id)}/sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ ...request, expectedCustodyEpoch }),
    });
  }

  async disableAccount(id: string, idempotencyKey: string, expectedCustodyEpoch: number): Promise<ManagedAccountSummary> {
    return this.request(`/v1/accounts/${encodeURIComponent(id)}/disable`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ expectedCustodyEpoch }),
    });
  }

  async restoreAccount(id: string, idempotencyKey: string, expectedCustodyEpoch: number): Promise<ManagedAccountSummary> {
    return this.request(`/v1/accounts/${encodeURIComponent(id)}/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ expectedCustodyEpoch }),
    });
  }

  async rotateCredential(
    id: string,
    idempotencyKey: string,
  ): Promise<CredentialRotationResponse> {
    return this.request(`/v1/credentials/${encodeURIComponent(id)}/rotate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
    });
  }

  async revokeCredential(id: string): Promise<{ success: boolean }> {
    return this.request(`/v1/credentials/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  async listManagedAccounts(externalUserId?: string): Promise<{ accounts: ManagedAccountSummary[] }> {
    return this.listAccounts(externalUserId ? { externalUserId } : {});
  }

  async getManagedAccount(id: string): Promise<ManagedAccountSummary> {
    return this.getAccount(id);
  }

  async getEntitlements(): Promise<{ entitlements: OrganizationEntitlements; usage: { managedAccounts: number } }> {
    return this.request('/v1/organization/entitlements');
  }

  async createWebhookEndpoint(url: string, eventTypes: OpenKeyLifecycleEvent[]): Promise<{
    endpoint: { id: string; url: string; eventTypes: OpenKeyLifecycleEvent[]; active: boolean; createdAt: string };
    secret: string;
  }> {
    return this.request('/v1/webhook-endpoints', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url, eventTypes }),
    });
  }

  async listWebhookEndpoints(): Promise<{ endpoints: Array<{ id: string; url: string; eventTypes: OpenKeyLifecycleEvent[]; active: boolean }> }> {
    return this.request('/v1/webhook-endpoints');
  }

  async disableWebhookEndpoint(id: string): Promise<{ success: true }> {
    return this.request(`/v1/webhook-endpoints/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  createTinyCloudSigner(input: {
    accountId: string;
    chainId?: number;
    getChainId?: () => number | Promise<number>;
    idempotencyKeyFactory?: () => string;
  }) {
    const nextKey = input.idempotencyKeyFactory ?? (() => generateState());
    const getChainId = input.getChainId ?? (() => input.chainId ?? 1);
    const getCurrentAccount = async () => this.getAccount(input.accountId);
    const toHexMessage = (message: Uint8Array) => `0x${Array.from(message).map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
    return {
      getAddress: async () => (await getCurrentAccount()).address,
      getChainId,
      signMessage: async (message: Uint8Array | string) => {
        const account = await getCurrentAccount();
        const payload = typeof message === 'string'
          ? { message }
          : { message: toHexMessage(message), format: 'hex' as const };
        const result = await this.sign(input.accountId, payload, nextKey(), account.custodyEpoch);
        return result.signature ?? result.signedTransaction ?? '';
      },
      signTypedData: async (typedData: SignTypedDataRequest) => {
        const account = await getCurrentAccount();
        const result = await this.sign(input.accountId, { typedData }, nextKey(), account.custodyEpoch);
        return result.signature ?? '';
      },
      signDigest: async (digest: `0x${string}`, auditContext: string) => {
        const account = await getCurrentAccount();
        const result = await this.sign(input.accountId, { digest, auditContext }, nextKey(), account.custodyEpoch);
        return result.signature ?? '';
      },
      signTransaction: async (transaction: unknown) => {
        const account = await getCurrentAccount();
        const result = await this.sign(input.accountId, { transaction }, nextKey(), account.custodyEpoch);
        return result.signedTransaction ?? result.signature ?? '';
      },
    };
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${this.serverCredential}`);
    const response = await this.fetchImpl(`${this.apiBaseUrl}${path}`, { ...init, headers });
    const body = await response.json().catch(() => ({})) as any;
    if (!response.ok) {
      const error = new Error(body?.error?.message ?? body?.error ?? `OpenKey API error ${response.status}`);
      Object.assign(error, { code: body?.error?.code ?? 'OPENKEY_API_ERROR', status: response.status });
      throw error;
    }
    return body as T;
  }
}

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
