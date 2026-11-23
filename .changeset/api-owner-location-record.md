---
"@openkey/api": patch
---

A first-party sign that asks to publish the owner's location creates the owner's public v1 location record, naming the default node, once the account's setup completes there. The record is created only when the registry has neither a v2 nor a v1 record for the owner, and a refused or conflicting create is final. Third-party and unattributed origins never trigger it, and it stays off until the sign request carries `publishOwnerLocation: true`.

Details: TC-4082
