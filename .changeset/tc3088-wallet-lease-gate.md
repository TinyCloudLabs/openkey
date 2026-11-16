---
"@openkey/api": patch
---

Renewal leases are now made only for accounts whose key OpenKey holds (TC-3088). When an account that signs with an external wallet ticks renewal, the approval goes ahead as a finite one: it ends at the grant's own end and no lease is made. A lease an external wallet signed can only be revoked by that wallet, so until it can be stopped by the operator kill, none is made.
