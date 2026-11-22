---
"@openkey/api": patch
---

A KV grant written `<space>/kv`, with no path, is a read of the whole space, so it is not held to 7 days. Signing, `/complete`, the managed `POST /delegate`, `/authorize-sign` and the frame's `/authorize-sign-preview` read that resource as the secrets vault and refused or cut a longer expiry to 7 days. `<space>/kv` and `<space>/kv/<path>` take the path after the `kv` segment; a read of `vault/secrets` or `secrets` and what is under them is held to 7 days as before, and a KV resource with no `kv` segment is held as the secrets vault.

Details: TC-3800
