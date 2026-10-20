---
"@openkey/api": patch
---

Auto-Sign (`POST /api/delegate/sign`) no longer signs a request that could write or delete in the agents space under `xyz.tinycloud.courier/me/approvals` or `me/orders`, including a whole-space write grant such as the agents bootstrap session. Those requests return `needsApproval` with code `owner_only_path` and need a passkey approval. Read-only agents-space requests, the agents space host delegation and every other space are unchanged.
