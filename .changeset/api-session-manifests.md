---
"@openkey/api": patch
---

The API's TinyCloud sessions declare the permissions they use. The dashboard `openkey` session asks for kv get, put, del and list under `variables`; the `secrets` session asks for the same actions under `vault/secrets/` and decrypt on the owner's default encryption network. Both keep a 30-day lifetime, set explicitly. The app review sessions ask for exactly the fixtures they write and read back, and the seed check for read on TinyChat's threads database.

Details: TC-3443
