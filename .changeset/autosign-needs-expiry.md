---
"@openkey/api": patch
---

Auto-Sign (`/api/delegate/sign`) does not sign a sign-in message with no `Expiration Time`: it answers `needsApproval` with code `auto_sign_needs_expiry`, and the TinyCloud SDKs report that answer as a failed sign-in. `/api/keys/:id/sign` and `/api/delegate/sign` log one `siwe_signed` line per sign-in message they sign, with the route, `siwe_expiry` (present or absent), whether it carries a ReCap and the client-claimed origin (`claimed_origin`, for counting only); never the message, address, nonce, key or user. Details: TC-3844
