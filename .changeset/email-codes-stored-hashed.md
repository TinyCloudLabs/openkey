---
"@openkey/api": patch
---

Email sign-in codes and account verification codes are stored as a keyed hash. Requesting a new sign-in code ends the earlier one. A code sent before this release needs to be requested again.

Details: TC-3422
