---
"@openkey/api": patch
---

`POST /api/secrets/enable` no longer runs the node SDK's account bootstrap inside each of its two sign-ins (TC-3115). For a first enable that bootstrap hosted and activated six spaces one request at a time and then aborted, about 9 s per sign-in against the production node, so the call took 17 to 20 s and ended in a gateway 502. The enable now takes about 3 to 5 s. OpenKey still provisions the account itself; the dashboard secrets and variables sessions are otherwise unchanged.
