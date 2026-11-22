---
"@openkey/api": minor
"@openkey/tee": minor
---

Anyone can ask OpenKey for its attestation without signing in. `GET /attestation?nonce=<nonce>` returns a fresh TDX quote, the event log, the compose hash and the app ID, with the same shape as tinycloud-node's `/attestation`. The quote's report data is SHA-256 of `so.openkey/tee-key/v1\0:<issuer>#<signing-key thumbprints>:<nonce>`, which binds it to the caller's nonce and to the keys OpenKey signs tokens with. Clients don't check it yet.

Details: TC-3842
