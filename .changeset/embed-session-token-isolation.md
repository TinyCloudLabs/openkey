---
"@openkey/sdk": patch
---

The SDK no longer receives, stores or forwards the OpenKey session token (TC-688). `getSessionToken()` now always returns `null`, `tinycloudSigningOptions().token` is always `null`, and connect, sign, sign-typed-data and sign-out widget messages carry no `sessionToken`. Embedded widgets read the session from OpenKey's own storage, so connect, sign and sign-typed-data work as before.

What breaks: code that used `getSessionToken()` as a bearer for OpenKey APIs. `/api/delegate/sign` already rejected that token (it accepts only OAuth access tokens), and `/api/keys/*` and `/api/account/*` now refuse it outside OpenKey. Use the OpenKey OAuth flow for server-side signing. In popup sign-out after an iframe-only sign-in, the popup can no longer revoke the iframe's session; iframe-mode sign-out (the default) still does.
