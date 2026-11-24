---
"@openkey/sdk": minor
---

New `OpenKey.requestRegistryChange({ nodes, spaces?, encryptionNode? })` and `OpenKey.requestRegistryUndo({ historyId })` let an app ask OpenKey to update or restore a person's TinyCloud location registry record. Both calls open the popup consent screen and resolve to `{ status: "published", sequence, recordHash } | { status: "cancelled" }`.

Details: TC-3893
