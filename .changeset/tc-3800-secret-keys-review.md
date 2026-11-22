---
"@openkey/capability-review": minor
---

Secret keys (TC-3800): `exactSecretKeyPath`, `secretOfKvPath`, `grantDecryptsOneSecret`, `allSecretsReach` with `allSecretsCard` (the all-secrets card's words), `approvalLifetimeCapSeconds` (7 days at most for a request that decrypts secrets), `decryptsSecrets`, and `secretLifetimeCapApplies` (whether a grant outside a signed approval request is held to 7 days: decrypt or key.create on a key or prefix under `secrets/`, and with `{ networkDecrypt: true }` a whole network's decrypt). An encryption resource that cannot be parsed counts as reaching secrets. `oneNamedSecret` now needs decrypt on the secret's own key, not the whole network, and its rows are one: "Read the secret NAME". A summary row may carry a `detail` line.
