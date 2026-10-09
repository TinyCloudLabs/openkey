---
"@openkey/sdk": patch
---

Sign-out, sign-in and signing no longer hang for 5 minutes inside an embedded app WebView. When the OpenKey iframe did not signal ready within 3 s, the SDK fell back to a popup, which Android WebView and iOS WKWebView (for example in Capacitor) cannot show, so the flow sat on a dead window until the timeout.

- In a known embedded WebView (Capacitor native, React Native WebView, Android `wv`, iOS WKWebView without Safari) the SDK now skips the popup fallback and rejects right away with `{ code: 'POPUP_BLOCKED' }`.
- Everywhere, a `window.open` that returns `null` or an already closed window now rejects right away with `POPUP_BLOCKED` instead of waiting on it. This also covers `mode: 'popup'` and `oauth.connect`.
- `signOut()` rejects with that error when the remote sign-out cannot complete. It never resolves as if it had succeeded. It still clears the SDK's local auth state first, and clearing the app's own session is the caller's decision.

No new error code was added; callers already handle `POPUP_BLOCKED`. Normal browsers behave as before: the iframe is tried first, then the popup fallback.
