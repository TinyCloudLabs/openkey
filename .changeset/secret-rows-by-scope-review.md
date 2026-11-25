---
"@openkey/capability-review": patch
---

`buildSummaryStatements` keeps one row per secret key. A scoped secret reads "Read the secret NAME in scope SCOPE" and carries its scope (`secret.scope`, taken from the key path), so the same name in two scopes is two Sensitive rows. The Sensitive count and the count of secret rows equal the number of secret keys a request names. `secretListLabel` lists a scoped secret as `SCOPE/NAME` and a global one as `NAME`; `secretReadParts` gives the runs of a read row so a face can set the name and the scope apart.

Details: TC-4349
