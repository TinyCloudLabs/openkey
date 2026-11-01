---
"@openkey/web": patch
---

With no suggested lifetime, the device page (`/device`) and the signed-approval page (`/delegate` approval link) now preselect the smaller of a week and the requester's signed maximum, instead of the maximum itself (which could be near-permanent). It changes only what is preselected: the owner can still pick anything up to the maximum, with the existing long-lifetime notice. A requester's own suggestion is unchanged. (Opus finding on TC-2274.)
