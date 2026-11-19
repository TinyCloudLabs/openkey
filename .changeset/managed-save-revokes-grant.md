---
"@openkey/api": patch
---

Managed approval saves that fail after activation now revoke the grant. `grantLifetimeSeconds` must be a positive whole number within the supported expiry range, and a managed retry after such a failure answers 409 "Renewal failed. Start a new request."

Details: TC-2789
