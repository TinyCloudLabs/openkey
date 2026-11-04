---
"@openkey/web": minor
---

Signing and connection selection use active keys. When a requested key is archived, the approval screen asks the owner to reconnect and reports `NO_KEY` with the same instruction to the requesting app. A named owner stays bound to its original request.

The shared key picker also serves message and typed-data signing requests that do not pin a key, plus prepared CLI handoffs. It offers the primary key first, keeps other usable keys available, and selects a sole usable key automatically. SIWE requests offer only keys matching the named signing account; explicit key identifiers keep their requested identity.

Details: TC-1496
