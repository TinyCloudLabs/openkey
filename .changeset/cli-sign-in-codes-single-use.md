---
"@openkey/api": patch
"@openkey/web": patch
---

CLI sign-in short codes are single-use and expire after 5 minutes. `GET /api/delegation-codes/:code` returns the delegation once and deletes the code. A second redeem, an expired code and an unknown code all return the same `404 Not found`. Lookups are capped at 60 per minute across all callers; beyond that the endpoint returns `429` with `Retry-After`. `/delegate` shows the 5-minute validity.
