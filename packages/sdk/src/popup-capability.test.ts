// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import { isEmbeddedAppWebView, isUsablePopup, popupUnavailableError } from './popup-capability';

const CHROME_ANDROID =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36';
const ANDROID_WEBVIEW =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.0.0 Mobile Safari/537.36';
const SAFARI_IOS =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const CHROME_IOS =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.0.0 Mobile/15E148 Safari/604.1';
const WKWEBVIEW =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148';
const DESKTOP_CHROME =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

describe('isEmbeddedAppWebView', () => {
  test('detects a native Capacitor platform', () => {
    expect(isEmbeddedAppWebView({ Capacitor: { isNativePlatform: () => true }, navigator: { userAgent: DESKTOP_CHROME } })).toBe(true);
  });

  test('does not treat Capacitor on the web as an embedded WebView', () => {
    expect(isEmbeddedAppWebView({ Capacitor: { isNativePlatform: () => false }, navigator: { userAgent: DESKTOP_CHROME } })).toBe(false);
    expect(isEmbeddedAppWebView({ Capacitor: {}, navigator: { userAgent: DESKTOP_CHROME } })).toBe(false);
  });

  test('detects React Native WebView', () => {
    expect(isEmbeddedAppWebView({ ReactNativeWebView: { postMessage() {} }, navigator: { userAgent: DESKTOP_CHROME } })).toBe(true);
  });

  test('detects Android WebView by the wv token', () => {
    expect(isEmbeddedAppWebView({ navigator: { userAgent: ANDROID_WEBVIEW } })).toBe(true);
  });

  test('detects iOS WKWebView (WebKit without Safari)', () => {
    expect(isEmbeddedAppWebView({ navigator: { userAgent: WKWEBVIEW } })).toBe(true);
  });

  test('leaves normal browsers alone', () => {
    for (const userAgent of [CHROME_ANDROID, SAFARI_IOS, CHROME_IOS, DESKTOP_CHROME]) {
      expect(isEmbeddedAppWebView({ navigator: { userAgent } })).toBe(false);
    }
    expect(isEmbeddedAppWebView({})).toBe(false);
  });

  test('is false with no window', () => {
    expect(isEmbeddedAppWebView()).toBe(false);
  });
});

describe('isUsablePopup', () => {
  test('rejects null, undefined and closed windows', () => {
    expect(isUsablePopup(null)).toBe(false);
    expect(isUsablePopup(undefined)).toBe(false);
    expect(isUsablePopup({ closed: true } as Window)).toBe(false);
  });

  test('accepts an open window', () => {
    expect(isUsablePopup({ closed: false } as Window)).toBe(true);
  });
});

describe('popupUnavailableError', () => {
  test('uses the existing POPUP_BLOCKED code with a WebView-specific message', () => {
    expect(popupUnavailableError(false)).toEqual({
      code: 'POPUP_BLOCKED',
      message: 'Popup was blocked. Please allow popups for this site.',
    });
    const embedded = popupUnavailableError(true);
    expect(embedded.code).toBe('POPUP_BLOCKED');
    expect(embedded.message).toContain('WebView');
    expect(embedded.reason).toBe('embedded-webview');
    expect('reason' in popupUnavailableError(false)).toBe(false);
  });
});
