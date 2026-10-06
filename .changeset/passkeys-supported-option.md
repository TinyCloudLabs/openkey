---
"@openkey/sdk": minor
---

Add a `passkeysSupported` option to `new OpenKey(...)` (default `true`). Clients where WebAuthn does not work, such as an ad-hoc-signed desktop webview, pass `false`; the SDK then opens every OpenKey widget (connect, sign, sign-typed-data, link-wallet, sign-out, Nostr, and the iframe-blocked popup fallback) with `passkeys=false`. Without the option, or with `true`, widget URLs are unchanged.
