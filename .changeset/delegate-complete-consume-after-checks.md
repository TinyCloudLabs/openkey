---
"@openkey/api": patch
---

`/api/delegate/complete` checks every binding (host, signed SIWE address and signature, signed expiry, user, session key, space, immutable SIWE fields, request baseline, action selection, and the device-transaction window) before it consumes the single-use authorization context, so a refused request leaves the pending approval usable. The context is consumed only when completion is about to succeed, by an atomic compare-and-delete: of two concurrent completions exactly one succeeds, and a replay is refused with `context-not-found`. The versioned managed approval (`POST /api/delegate`) likewise checks the signed expiry and device window before consuming its context. A missing signed expiry is now reported as such instead of `immutable-fields-changed`.
