---
"@openkey/api": patch
---

Renewal leases are now made only for accounts whose key OpenKey holds (TC-3088). Ticking renewal on an account that signs with an external wallet is refused with `renewal_external_wallet` at `/api/delegate/prepare` and on the wallet completion path, and nothing is approved. A finite choice is unaffected. A lease an external wallet signed can only be revoked by that wallet, so until it can be stopped by the operator kill, none is made.
