// Detects when a popup cannot work, so flows fail fast instead of waiting on
// a window that will never answer (embedded app WebViews cannot open popups).

export interface PopupError {
  code: 'POPUP_BLOCKED';
  message: string;
}

type PopupEnvironment = {
  Capacitor?: { isNativePlatform?: () => boolean };
  ReactNativeWebView?: unknown;
  navigator?: { userAgent?: string };
};

/** True inside a known embedded app WebView, where `window.open` cannot show a popup. */
export function isEmbeddedAppWebView(env?: PopupEnvironment): boolean {
  const target = env ?? (typeof window === 'undefined' ? undefined : (window as unknown as PopupEnvironment));
  if (!target) return false;

  if (target.Capacitor?.isNativePlatform?.() === true) return true;
  if (target.ReactNativeWebView) return true;

  const userAgent = target.navigator?.userAgent ?? '';
  // Android WebView adds a `wv` token to the platform comment.
  if (/\bAndroid\b[^)]*;\s*wv\b/.test(userAgent)) return true;
  // iOS WKWebView sends an Apple WebKit UA without the `Safari/` token that
  // Safari and the iOS browsers built on WebKit (Chrome, Firefox, Edge) add.
  if (/\b(iPhone|iPad|iPod)\b/.test(userAgent) && /AppleWebKit/.test(userAgent) && !/Safari\//.test(userAgent)) {
    return true;
  }
  return false;
}

/** `window.open` returns null when blocked, and can return an already-closed window. */
export function isUsablePopup(popup: Window | null | undefined): popup is Window {
  return !!popup && popup.closed !== true;
}

export function popupUnavailableError(embeddedWebView: boolean): PopupError {
  return {
    code: 'POPUP_BLOCKED',
    message: embeddedWebView
      ? 'Popups are not available in this embedded app WebView. Make sure the OpenKey host is allowed by frame-src, or use native sign-in.'
      : 'Popup was blocked. Please allow popups for this site.',
  };
}
