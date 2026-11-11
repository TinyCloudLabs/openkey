---
"@openkey/api": minor
---

Return optional requester-bound confirmation codes after durable approval. Requesters can collect a code through signed result discovery and continue through the existing encrypted fetch and acknowledgement flow. Codes expire within five minutes and no later than result retention. Ordinary signed collection remains available without a code.

Details: TC-2489.
