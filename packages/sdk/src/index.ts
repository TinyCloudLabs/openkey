// OpenKey SDK - Browser client for third-party apps
// Provides "Sign with OpenKey" functionality via popup or iframe

export interface OpenKeyConfig {
  /** OpenKey host URL (default: https://openkey.so) */
  host?: string;
  /** App identifier for display */
  appName?: string;
  /** Use popup instead of iframe (default: true) */
  usePopup?: boolean;
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
}

export interface OpenKeyError {
  code: 'USER_CANCELLED' | 'POPUP_BLOCKED' | 'TIMEOUT' | 'NO_KEY' | 'UNAUTHORIZED' | 'UNKNOWN';
  message: string;
}

type MessageType =
  | { type: 'openkey:auth:request'; appName: string }
  | { type: 'openkey:auth:response'; success: true; address: string; keyId: string }
  | { type: 'openkey:auth:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:sign:request'; message: string; keyId?: string }
  | { type: 'openkey:sign:response'; success: true; signature: string; address: string }
  | { type: 'openkey:sign:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:signTypedData:request'; data: SignTypedDataRequest }
  | { type: 'openkey:signTypedData:response'; success: true; signature: string; address: string }
  | { type: 'openkey:signTypedData:response'; success: false; error: OpenKeyError }
  | { type: 'openkey:ready' }
  | { type: 'openkey:close' };

const DEFAULT_HOST = 'https://openkey.so';
const POPUP_WIDTH = 400;
const POPUP_HEIGHT = 600;
const DEFAULT_TIMEOUT = 5 * 60 * 1000; // 5 minutes

export class OpenKey {
  private host: string;
  private appName: string;
  private usePopup: boolean;
  private popup: Window | null = null;
  private iframe: HTMLIFrameElement | null = null;

  constructor(config: OpenKeyConfig = {}) {
    this.host = config.host || DEFAULT_HOST;
    this.appName = config.appName || window.location.hostname;
    this.usePopup = config.usePopup ?? true;
  }

  /**
   * Connect to OpenKey and get user's wallet address
   * Opens auth flow for user to select/create a key
   */
  async connect(): Promise<AuthResult> {
    return this.openFlow<AuthResult>('connect', {
      type: 'openkey:auth:request',
      appName: this.appName,
    });
  }

  /**
   * Sign a message with the user's OpenKey wallet
   */
  async signMessage(request: SignMessageRequest): Promise<SignResult> {
    return this.openFlow<SignResult>('sign', {
      type: 'openkey:sign:request',
      message: request.message,
      keyId: request.keyId,
    });
  }

  /**
   * Sign typed data (EIP-712) with the user's OpenKey wallet
   */
  async signTypedData(request: SignTypedDataRequest): Promise<SignResult> {
    return this.openFlow<SignResult>('sign-typed-data', {
      type: 'openkey:signTypedData:request',
      data: request,
    });
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
        data.type === 'openkey:signTypedData:response'
      ) {
        cleanup();
        this.popup?.close();

        if (data.success) {
          if (data.type === 'openkey:auth:response') {
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
        data.type === 'openkey:signTypedData:response'
      ) {
        cleanup();

        if (data.success) {
          if (data.type === 'openkey:auth:response') {
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
