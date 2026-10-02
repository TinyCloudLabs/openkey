---
"@openkey/api": minor
---

Device authorization accepts an explicit, bounded manifest permission set (KV and the required `tinycloud.capabilities/read`) with an optional reason and a 30-day maximum lifetime, rejects out-of-policy device scopes with `invalid_scope`, binds and relays exactly the capabilities the owner approves, and refuses device delegations outside the transaction's key, Node origin, or lifetime before signing or host activation. Deploy after the matching web change; the legacy Share-only request is unchanged.
