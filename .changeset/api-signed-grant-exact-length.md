---
"@openkey/api": patch
---

A signed grant lasts exactly the length the owner chose. The signed Expiration Time is the request's Issued At plus that length, to the second, in the approval preview and in the signature that follows it. A length that ends before the present moment, counted from Issued At, is refused and the request starts again.

Details: TC-3920
