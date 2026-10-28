---
"@openkey/api": minor
"@openkey/web": minor
"@openkey/db": minor
---

Add immutable signed CLI approval requests at `/a/<id>#v=4&k=<key>&c=<sealedBodyCid>` using the existing delegation consent and signed proof. Results are encrypted for the requester, repeatably fetched, and cleared only by an authenticated idempotent ACK after the CLI's durable save.

Deployment requires the additive approval-request migration and an explicit `APPROVAL_RESULT_RETENTION_SECONDS` (60–86400 seconds). No production retention default is selected. The local synthetic runner uses 600 seconds, independently of request and grant expiry. `APPROVAL_LINKS_API_ORIGIN` defaults to `https://api.tinycloud.xyz`; `APPROVAL_OPENKEY_ORIGIN` defaults to `https://openkey.so`. The development-only `APPROVAL_LINKS_LOCAL_TRANSPORT` can forward to configured HTTP loopback without changing the signed HTTPS audience.

The consumer release must follow the shared codec artifact from SDK source `63fd3a7de34d3b6f364430eb8a82caa803c7f659`. Until that artifact is released, local proof uses its immutable packed artifact, not a fictitious npm version or a permanent development path. Legacy login, device authorization, manual five-minute codes, Share and Courier are unchanged.
