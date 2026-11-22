---
"@openkey/capability-review": minor
---

Secret keys: `exactSecretKeyPath`, `secretOfKvPath`, `grantDecryptsOneSecret`, `allSecretsReach` with `allSecretsCard` (the all-secrets card's words), `approvalLifetimeCapSeconds` (7 days at most for a request that decrypts secrets), `decryptsSecrets` and `secretLifetimeCapApplies` (whether a grant outside a signed approval request is held to 7 days: decrypt or key.create on a key or prefix under `secrets/`, a KV read of the secrets vault or any action of the `secrets` service; with `{ networkDecrypt: true }` also a whole network's decrypt). An encryption resource that cannot be parsed counts as reaching secrets. `oneNamedSecret` needs decrypt on the secret's own key, not the whole network, and its rows are one: "Read the secret NAME". A summary row may carry a `detail` line.

Details: TC-3800
