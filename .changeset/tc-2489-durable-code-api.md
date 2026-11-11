---
"@openkey/api": minor
---

Return optional requester-bound confirmation codes after durable approval. Requesters can collect a code through result discovery signed over the code hash and saved claim hash and continue through the existing encrypted fetch and acknowledgement flow. Codes expire within five minutes and no later than result retention. Ordinary signed collection remains available without a code.

Details: TC-2489.
