---
"@openkey/api": patch
---

A sign-in request whose SIWE Issued At is more than 5 minutes ahead of the server clock is refused with `invalid_siwe_header` when the request is prepared, and no approval context is issued for it. An Issued At up to 5 minutes ahead is accepted to allow for clock skew between the app and the server.

Details: TC-4212
