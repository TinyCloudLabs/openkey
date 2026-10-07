---
"@openkey/core": minor
---

Add the platform-agnostic native TinyCloud delegation module (`native-delegation.ts`): validated RFC 8414 discovery, PAR and authorize-URL builders for `tinycloud_delegation` authorization details, Ed25519 session keypairs with `did:key` and JWK serializations, the `OpenKey-Session-Proof` compact JWS signer, RFC 9207 `iss`/`state`/`error` callback parsing, token/renew/revoke clients with injectable fetch and delegation response validation, and the `OpenKeyNativeError` code set.
