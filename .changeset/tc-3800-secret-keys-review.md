---
"@openkey/capability-review": minor
---

Secret keys (TC-3800): `exactSecretKeyPath`, `secretOfKvPath`, `grantDecryptsOneSecret`, `allSecretsReach` with `allSecretsCard` (the all-secrets card's words), and `approvalLifetimeCapSeconds` (7 days at most for a request that decrypts secrets). `oneNamedSecret` now needs decrypt on the secret's own key, not the whole network, and its rows are one: "Read the secret NAME". A summary row may carry a `detail` line.
