---
"@openkey/sdk": patch
---

Correct the `manifestDigest` type comment: the app-key manifest at `/.well-known/openkey-manifest.json` is fetched from the app's origin and digest-checked, not signed, and it is optional for app keys. See docs/app-keys-for-builders.md.
