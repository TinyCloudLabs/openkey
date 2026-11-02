---
"@openkey/api": patch
---

`GET /health` reports `version` (the API package version) and `commit` (the `GIT_SHA` build argument, or `unknown` when it is not set) next to the existing fields. Status codes and the not-ready response are unchanged.

Details: TC-1881
