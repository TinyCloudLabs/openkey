---
"@openkey/api": patch
---

A first-party sign that asks to publish the owner's location creates the owner's public v1 location record, naming the default node. A sign that completes the account's setup on that node triggers it. An existing account is covered on its next first-party sign when consent allows: a stored complete setup is only a hint, so the API first asks the node for a fresh answer, with one short session delegation that carries only the `tinycloud.kv/list` ability on the account space and one list call. Any answer but a 2xx list skips the publish. The record is created only when the registry has neither a v2 nor a v1 record for the owner, and a refused or conflicting create is final. A per-process memo checks each owner at most once every five minutes. Third-party and unattributed origins never trigger it, and it stays off until the sign request carries `publishOwnerLocation: true`.

Details: TC-4082
