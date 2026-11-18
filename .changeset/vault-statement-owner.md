---
"@openkey/capability-review": patch
---

A secrets vault request whose owner is not known now reads "View secrets stored in the requested vault" or "Manage secrets stored in the requested vault", and another user's vault reads "another user's vault", instead of "your vault".

Details: TC-3157
