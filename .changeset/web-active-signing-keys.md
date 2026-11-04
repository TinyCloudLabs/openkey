---
"@openkey/web": patch
---

Signing and connection selection use active keys. When a requested key is archived, the approval screen asks the owner to reconnect and reports `NO_KEY` with the same instruction to the requesting app. A named owner stays bound to its original request. Details: TC-1496
