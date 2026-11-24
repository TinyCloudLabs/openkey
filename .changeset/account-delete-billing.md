---
"@openkey/api": patch
---

Deleting an account cancels its billing subscription first and records that a deletion happened, with no identifier for the account. If billing can't be reached, nothing is deleted.

Details: TC-3903
