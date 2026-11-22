---
"@openkey/api": minor
"@openkey/tee": minor
---

The settings that decide who can sign (issuer URL, passkey relying party and account origin, Google client id, OAuth registration and audiences, node stats URL and the native renewal switch) are fixed values in the measured production compose, not encrypted-env values, which `compose_hash` doesn't cover. Inside the TEE the API refuses to start unless each of them, and the Apple ids and renewal settings the compose already fixes, is a literal in the compose it was measured with and the process sees exactly that value. `@openkey/tee` adds `measuredAppCompose()`. Deploys probe the live issuer, rpId, CORS origins, account origin and Google client id afterwards.

Details: TC-3840
