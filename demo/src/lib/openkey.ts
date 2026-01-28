// OpenKey SDK wrapper for popup-based message signing

import { OPENKEY_HOST } from './oauth';

export interface SignResult {
  signature: string;
  address: string;
}

export interface OpenKeyError {
  code: string;
  message: string;
}

interface SignResponse {
  type: 'openkey:sign:response';
  success: boolean;
  signature?: string;
  address?: string;
  error?: OpenKeyError;
}

interface CloseMessage {
  type: 'openkey:close';
}

type PopupMessage = SignResponse | CloseMessage;

export class OpenKeyClient {
  private host: string;
  private popup: Window | null = null;

  constructor(host: string = 'https://openkey.so') {
    this.host = host;
  }

  /**
   * Sign a message using OpenKey's widget popup.
   * Opens a popup window that prompts the user to approve the signature.
   */
  async signMessage(message: string, keyId?: string): Promise<SignResult> {
    return new Promise((resolve, reject) => {
      // Build popup URL
      const popupUrl = new URL('/widget/sign', this.host);
      popupUrl.searchParams.set('origin', window.location.origin);

      // Calculate popup dimensions and position
      const width = 420;
      const height = 600;
      const left = Math.max(0, window.screenX + (window.outerWidth - width) / 2);
      const top = Math.max(0, window.screenY + (window.outerHeight - height) / 2);

      // Open popup
      this.popup = window.open(
        popupUrl.toString(),
        'openkey-sign',
        `width=${width},height=${height},left=${left},top=${top},popup=yes`
      );

      if (!this.popup) {
        reject({
          code: 'POPUP_BLOCKED',
          message: 'Popup was blocked. Please allow popups for this site.',
        } as OpenKeyError);
        return;
      }

      let resolved = false;

      const handleMessage = (event: MessageEvent<PopupMessage>) => {
        // Verify origin
        if (event.origin !== this.host) return;

        const data = event.data;
        if (!data || typeof data !== 'object') return;

        if (data.type === 'openkey:sign:response') {
          resolved = true;
          cleanup();

          if (data.success && data.signature && data.address) {
            resolve({
              signature: data.signature,
              address: data.address,
            });
          } else {
            reject(data.error || {
              code: 'SIGNING_FAILED',
              message: 'Signing failed',
            });
          }
        } else if (data.type === 'openkey:close') {
          if (!resolved) {
            resolved = true;
            cleanup();
            reject({
              code: 'USER_CANCELLED',
              message: 'User cancelled the signing request',
            } as OpenKeyError);
          }
        }
      };

      const checkPopupClosed = setInterval(() => {
        if (this.popup?.closed && !resolved) {
          resolved = true;
          cleanup();
          reject({
            code: 'USER_CANCELLED',
            message: 'User closed the popup',
          } as OpenKeyError);
        }
      }, 500);

      const cleanup = () => {
        window.removeEventListener('message', handleMessage);
        clearInterval(checkPopupClosed);
        if (this.popup && !this.popup.closed) {
          this.popup.close();
        }
        this.popup = null;
      };

      window.addEventListener('message', handleMessage);

      // Wait for popup to load, then send the sign request
      const sendRequest = () => {
        if (this.popup && !this.popup.closed) {
          this.popup.postMessage(
            {
              type: 'openkey:sign:request',
              message,
              keyId,
            },
            this.host
          );
        }
      };

      // Send request after a short delay to ensure popup is ready
      setTimeout(sendRequest, 500);
      // Also try again after a longer delay in case of slow load
      setTimeout(sendRequest, 1500);
    });
  }
}

// Default client instance using configured host
export const openkey = new OpenKeyClient(OPENKEY_HOST);
