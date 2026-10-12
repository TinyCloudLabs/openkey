---
"@openkey/api": patch
---

`/api/delegate` and `/api/delegate/prepare` now plan TinyCloud space onboarding when the request names either TinyCloud node host, `https://node.tinycloud.xyz` or `https://tee.node.tinycloud.xyz` (which Courier and node-sdk send). Hosts match exactly after lowercasing and stripping one trailing slash; no other host qualifies. Bootstrap and its completion state always use the configured `TINYCLOUD_BOOTSTRAP_HOST`, so the two names share one setup record. Session activation still uses the host the client sent (TC-943).
