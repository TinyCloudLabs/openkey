---
"@openkey/api": minor
"@openkey/tee": minor
---

Anyone can ask OpenKey for its attestation without signing in. `GET /attestation?nonce=<nonce>` returns a fresh TDX quote, the event log, the compose hash and the app ID. It follows tinycloud-node's `/attestation`, except that it returns `identity` and `excluded_keys` where the node returns `enforcer_did`. The quote's report data is SHA-256 of `so.openkey/tee-key/v1\0:<issuer>#<thumbprints>:<nonce>`. The thumbprints are of the keys this measured code holds and signs with; the keys are stored in the database. A served key counts only when OpenKey can open its private key and that key signs a fresh challenge the public key verifies; other served keys are left out and counted. Clients don't check it yet.

Details: TC-3842
