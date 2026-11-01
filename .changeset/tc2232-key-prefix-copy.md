---
"@openkey/capability-review": patch
---

The approval list no longer shows literal backquotes around a key prefix ("Create your own encryption keys in qa/"), and the owner's `share/` prefix reads "Create keys for files you share". The callout above the list now counts the Sensitive rows that reach secrets or decryption, not grants: a `share/` request that creates keys and decrypts is two Sensitive rows and was counted once. New export: `sensitiveRowCount`.

Details: TC-2232
