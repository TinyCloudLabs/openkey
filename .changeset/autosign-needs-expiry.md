---
"@openkey/api": patch
---

Auto-Sign (`/api/delegate/sign`) no longer signs a sign-in message with no `Expiration Time` on its own: it answers `needsApproval` with code `auto_sign_needs_expiry`, so the owner decides on the approval screen. `/api/keys/:id/sign` and `/api/delegate/sign` log one `siwe_signed` line per sign-in message they sign, with the route, `siwe_expiry` (present or absent), whether it carries a ReCap and the app origin; never the message, address, nonce, key or user. Details: TC-3844
