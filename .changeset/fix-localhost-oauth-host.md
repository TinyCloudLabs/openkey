---
"@openkey/sdk": patch
---

Fix OAuth host derivation for localhost: skip `api.` prefix for localhost/127.0.0.1 since the OAuth API is behind the same proxy in local development.
