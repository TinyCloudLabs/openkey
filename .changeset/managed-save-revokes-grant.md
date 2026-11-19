---
"@openkey/api": patch
---

Managed approval saves that fail after activation now revoke the grant. `grantLifetimeSeconds` must be a positive whole number within the supported expiry range. Retrying a managed approval after such a failure needs a new request.

Details: TC-2789
