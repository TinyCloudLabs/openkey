---
"@openkey/api": patch
---

Sign-in messages that name an encryption key under `apps/`, and messages that grant `key.delete`, are refused by the delegate, key-signing, prepared-handoff and device sign-in routes with `app_key_grant_refused` or `key_delete_not_grantable`. A sign-in message whose ReCap cannot be read exactly is refused with `invalid_siwe_recap`, and `/authorize-sign-prepare` answers 400 `invalid_siwe` when `siwe` is not a string. Encryption key URNs are parsed by one shared parser (`key-resource`). Details: TC-1777
