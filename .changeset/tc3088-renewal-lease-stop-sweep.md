---
"@openkey/api": patch
---

Setting `OPENKEY_RENEWAL_LEASES=stop` now turns renewal leases off and also stops the ones already granted (TC-3088). Before, any value other than `enabled` only stopped new leases, and the node kept renewing granted ones. With `stop`, the API revokes every live lease that an OpenKey-held key signed, every 5 minutes, and retries any the node did not confirm. Leases signed by an external wallet can only be revoked by that wallet; each pass logs how many are left. Nothing changes for any other value.
