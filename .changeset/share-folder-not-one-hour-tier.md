---
"@openkey/capability-review": patch
---

`grantIsBroadOnce` places the signer's own `default/share/` folder, and any prefix under it, outside the one-hour approval tier, so a request for it starts at the length the app asked for. The new `grantIsOwnShareFolder` names that folder: decrypt or key.create on `default/share/` or a prefix under it, owned by the signer. An exact share key, another owner's folder, another network, the whole network, every other prefix outside `apps/<appId>/`, the vault and any shape it cannot place are in the tier.

Details: TC-3821
