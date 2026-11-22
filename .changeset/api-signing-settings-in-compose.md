---
"@openkey/api": minor
"@openkey/tee": minor
---

The settings that decide who can sign (issuer URL, passkey relying party, Google client id, OAuth registration and audiences, Apple ids, renewal settings, the ingress gateway) are fixed values in the measured production compose instead of encrypted-env values, which `compose_hash` does not cover. Inside the TEE the API refuses to start unless each is a literal in the compose it was measured with and the process sees exactly that value; `@openkey/tee` adds `measuredAppCompose()`. Deploys check the gateway against the CVM before deploying and probe the live issuer, rpId, CORS origins, account origin and Google client id afterwards. Details: TC-3840
