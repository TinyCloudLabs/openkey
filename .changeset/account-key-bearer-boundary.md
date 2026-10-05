---
"@openkey/api": patch
---

`/api/keys/*` (including `/api/keys/nostr/*`) and `/api/account/*` refuse a bearer token unless the request comes from an OpenKey web origin (TC-688). `PATCH /api/account/auto-sign` and `POST /api/account/delete` accept only a cookie session from an OpenKey origin. Account deletion also requires a passkey verification on the current session within the last five minutes (TC-689). `POST /api/account/delete/request` returns 501 instead of claiming to send an email.

What breaks: server-side callers using a Better Auth session token on these routes get 403. `POST /api/account/delete` has no web UI yet, and no current sign-in path records passkey freshness on a cookie session, so it is unusable until a passkey step-up flow is added.
