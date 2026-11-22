---
"@openkey/capability-review": minor
---

`grantIsBroadOnce` says whether a capability grant falls in the one-hour approval tier: access that can open all secrets or all encrypted data. That is decryption on a whole network, on a one-segment prefix or on a prefix outside `apps/<appId>/`. The tier also holds KV or secrets-service access to the whole vault and any shape the function cannot place. One named secret, a secret sub-prefix, the secret catalog in SQL, an exact key and a prefix inside `apps/<appId>/` fall outside it.

Details: TC-3111
