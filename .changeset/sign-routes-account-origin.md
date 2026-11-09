---
"@openkey/api": patch
---

Tighten which browser origins may call managed-key signing routes (`/api/keys/:id/sign`, `/api/keys/:id/sign-typed-data`, nostr sign-event and grants, `POST /api/delegate/sign`, and `POST /api/device-authorizations/:id/approve`): only the account-facing web origins are accepted; the admin console host is no longer allowlisted there. Credentialed CORS and Better Auth trusted origins are unchanged, so the console keeps its own API calls and sign-in.
