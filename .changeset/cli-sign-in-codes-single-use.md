---
"@openkey/api": patch
"@openkey/web": patch
---

CLI sign-in short codes are single-use and expire after 5 minutes. `GET /api/delegation-codes/:code` returns the delegation once and deletes the code. A second redeem, an expired code, and an unknown code all return the same `404 Not found`. The endpoint accepts at most 60 redeem attempts per minute and returns `429` with `Retry-After` beyond that. `/delegate` shows the 5-minute validity.
