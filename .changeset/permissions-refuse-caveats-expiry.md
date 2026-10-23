---
"@openkey/api": patch
---

`POST /api/delegate`, `POST /api/delegate/prepare`, and `POST /api/delegate/complete` now refuse a `permissions[]` entry that carries a `caveats` value that restricts anything, or an `expiry` or `expiryMs` value. The request fails with HTTP 400 and code `invalid_permissions`, and nothing is approved. These fields were previously dropped without an error. `caveats: []` and `caveats: [{}]` are still accepted. Other unknown permission fields are still dropped, and each dropped field name is logged as `permission_entry_unknown_field` (TC-1854).
