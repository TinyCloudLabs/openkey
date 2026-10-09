---
'@openkey/core': patch
---

Expose an optional token-exchange callback that lets native SDKs durably record an issued refresh token before delegation validation, and add a distinct `STORAGE` native error code for local secure-store failures.
