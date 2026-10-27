---
"@openkey/capability-review": patch
---

A decrypt on the account's `:default` encryption network reads "Decrypt protected data" again, on the sign-in consent screen and on the CLI `/device` approval, replacing the long default-key sentence added in TC-1730. A default-network grant that carries encryption setup and decrypt shows one row, "Set up encrypted data access and decrypt protected data", not two. Display text only: the signed request and the delegation content are unchanged. Details: TC-2198
