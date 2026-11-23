---
"@openkey/api": patch
---

A KV grant written `<space>/kv`, with no path, is a read of the whole space and keeps the length the app asked for on signing, `/complete`, the managed `POST /delegate`, `/authorize-sign` and the frame's `/authorize-sign-preview`. `<space>/kv` and `<space>/kv/<path>` take the path after the `kv` segment. A read of `vault/secrets` or `secrets`, or of anything under them, is held to 7 days, and a KV resource with no `kv` segment is held as the secrets vault.

Details: TC-3800
