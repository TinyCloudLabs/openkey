---
"@openkey/api": patch
---

`POST /api/delegate`, `POST /api/delegate/prepare`, and `POST /api/delegate/complete` refuse a `permissions[]` entry that carries a `caveats` value restricting anything, or an `expiry` or `expiryMs` value. The request fails with HTTP 400 and code `invalid_permissions`, and nothing is approved. `caveats: []` and `caveats: [{}]` are still accepted. Other unknown permission entry fields are ignored, and their names are logged as `permission_entry_unknown_field`.
