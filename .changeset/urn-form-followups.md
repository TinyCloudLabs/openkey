---
"@openkey/api": patch
---

`/api/delegate/authorize-sign` reshapes an entry for the consumer only when the ReCap parser reported it as a raw encryption resource (`space: "encryption"` and a `urn:tinycloud:encryption:` path); no other entry is touched. Details: TC-1783
