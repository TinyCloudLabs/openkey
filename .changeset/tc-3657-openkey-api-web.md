---
"@openkey/api": minor
"@openkey/web": minor
"@openkey/db": minor
---

TC-3657: OpenKey now exposes a one-tap TinyCloud setup for outside apps. When an outside app's sign-in refuses a brand-new owner, the app's SDK call to `OpenKey.authorizeTinyCloudSetup()` opens a top-level popup in OpenKey's own origin; on the owner's tap OpenKey signs the account's registry location record with the owner's key and publishes it. The outside app never sees the signed record and never chooses the TinyCloud node — OpenKey server fills the record's node DID and origin from its own allowlisted configuration.

New endpoints:
- `POST /api/tinycloud-setup/mint-ticket` — called by the setup widget after it observes the outside app's origin via `window.opener` postMessage. Returns an opaque one-time ticket bound to the owner, the browser-verified requesting origin, and the hash of the exact payload the server will sign.
- `POST /api/tinycloud-setup/publish` — the widget calls this on the owner's tap; the server verifies the ticket + a passkey assertion (when the owner's `passkeyApprovalMode` requires it), consumes the ticket, signs the canonical payload with the owner's primary TEE-sealed key, and PUTs the record to the location registry. Returns `{ status: "published" | "already-current" | "unavailable" }`.

New widget page: `/widget/tinycloud-setup` (popup-only; `Content-Security-Policy: frame-ancestors 'none'` + `X-Frame-Options: DENY` are set in `apps/web/src/hooks.server.ts` so they reach the HTML document even with `ssr=false`; a client-side `window.top !== window.self` guard refuses embedded renders if a proxy strips the header).

New Postgres tables (migration `20261121_0001_tinycloud_setup_tables`):
- `tinycloud_setup_consumed_nonce` — stores each consumed ticket's nonce; a replayed ticket is refused across API restarts AND across API replicas by a unique constraint on the nonce column (Bobbie C1 single-use invariant, Naomi 15:12:55Z durability).
- `tinycloud_setup_rate_limit_bucket` — atomic UPSERT counter keyed by `{action, subject, windowStartMs}`; parallel API replicas share one counter per owner per action per hour, so the C5 per-owner limit is global, not per-process.

New config: `TINYCLOUD_DEFAULT_NODE_DID` env (canonical Ed25519 `did:key:z…`) and `OPENKEY_SETUP_TICKET_SECRET` (hex, ≥32 bytes). The setup endpoints return `503 setup_unavailable` until both are set in each environment — fail-closed per Bobbie C1. When `OPENKEY_SETUP_TICKET_SECRET` is unset, the router's deps resolve lazily per request and 503 the endpoint; OpenKey as a whole still boots (F5 lazy init, 15:16:27Z).

Deploy order: run the Prisma migration, deploy API with the new config and endpoints, then web, then SDK publish.

Details: TC-3657.
