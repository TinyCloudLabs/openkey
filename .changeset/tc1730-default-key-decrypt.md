---
"@openkey/capability-review": patch
---

A raw `tinycloud.encryption/decrypt` on the account's `:default` network now reads "Decrypt anything encrypted with your account's default key — including your Secrets and every private share — whenever this app gets hold of the encrypted copy, until this access expires." The sentence is exported as `DECRYPT_DEFAULT_KEY_STATEMENT` from `copy.ts`. Decrypt on any other network, and decrypt on the default network with a sub-path, keep "Decrypt protected data". The combined "Set up encrypted data access and decrypt protected data" copy is unchanged.
