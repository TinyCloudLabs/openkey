---
"@openkey/api": minor
"@openkey/web": minor
---

TC-3657: OpenKey now exposes a one-tap TinyCloud setup for outside apps. When an outside app's sign-in refuses a brand-new owner, the app's SDK call to `OpenKey.authorizeTinyCloudSetup()` opens a top-level popup in OpenKey's own origin; on the owner's tap OpenKey signs the account's registry location record with the owner's key and publishes it. The outside app never sees the signed record and never chooses the TinyCloud node — OpenKey server fills the record's node DID and origin from its own allowlisted configuration.

New endpoints:
- `POST /api/tinycloud-setup/mint-ticket` — called by the setup widget after it observes the outside app's origin via `window.opener` postMessage. Returns an opaque one-time ticket bound to the owner, the browser-verified requesting origin, and the hash of the exact payload the server will sign.
- `POST /api/tinycloud-setup/publish` — the widget calls this on "Publish and continue"; the server verifies the ticket, consumes it, signs the canonical payload with the owner's primary TEE-sealed key, and PUTs the record to the location registry. Returns `{ status: "published" | "already-current" | "unavailable" }`.

New widget page: `/widget/tinycloud-setup` (popup-only; `Content-Security-Policy: frame-ancestors 'none'` and a client-side `window.top !== window.self` guard refuse embedded renders).

New config: `TINYCLOUD_DEFAULT_NODE_DID` env (canonical Ed25519 `did:key:z…`). Both setup endpoints return `503 setup_unavailable` until this is set in each environment, so no record can be signed pointing at an unverified node. Amos sets this in production before the endpoint is exposed.

Deploy order: API with the new config and endpoints, then web, then SDK publish.

Details: TC-3657.
