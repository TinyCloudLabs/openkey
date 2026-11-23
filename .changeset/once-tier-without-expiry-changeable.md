---
"@openkey/api": patch
"@openkey/web": patch
---

A sign-in whose grants reach all secrets or all encrypted data (decrypt on `default/secrets/`, on the whole encryption network, or a KV read of the secrets vault) offers the "How long it lasts" choice and starts at 1 hour whether or not the app sent `expiryChangeable`, and the owner may choose up to 7 days. An approval the owner leaves alone signs 1 hour; the app's own time applies when it is an hour or less. Grants outside that tier behave as the app asked.

Details: TC-3966
