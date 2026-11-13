---
"@openkey/web": patch
---

Target legacy Sign replies to the requesting window's browser origin. Ignore opaque request origins. SDK callers pass a concrete origin and retain their existing bootstrap.
