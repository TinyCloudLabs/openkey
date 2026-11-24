---
"@openkey/api": patch
---

A sign-in request whose SIWE Issued At or Not Before is more than 5 minutes ahead of the server clock is refused with `invalid_siwe_header` when the request is prepared, and no approval context is issued for it. A signed approval request header whose Issued At is more than 5 minutes ahead of the server clock is refused with `invalid_request`. A time up to 5 minutes ahead is accepted to allow for clock skew between the app and the server.

Details: TC-4212
