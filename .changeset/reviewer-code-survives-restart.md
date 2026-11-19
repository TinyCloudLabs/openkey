---
"@openkey/api": patch
"@openkey/db": patch
---

An installed app-review code now survives an API restart: its SHA-256 digest is stored with the review account and restored on start. Revoking the code, pinning a new audience, resetting the account and any hold clear it.

Details: TC-2775
