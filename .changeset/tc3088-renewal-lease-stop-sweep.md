---
"@openkey/api": patch
---

`OPENKEY_RENEWAL_LEASES=stop` turns renewal leases off and also stops the ones already granted. The API revokes every live lease an OpenKey-held key signed, every 5 minutes, and retries any the node didn't confirm. Leases signed by an external wallet can only be revoked by that wallet; each pass logs how many are left. Other values are unchanged.

Details: TC-3088
