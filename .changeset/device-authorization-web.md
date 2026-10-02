---
"@openkey/web": minor
---

`/device` and `/delegate` show every capability of a device authorization request, enforce a same-device acknowledgement, verify the `/delegate` link (keys, origins, scope, lifetime) against the server's pending request, use the server-cleaned reason, offer lifetimes only up to the requested one, and relay exactly the approved subset. Works with the current API; legacy Share-only requests are unchanged.
