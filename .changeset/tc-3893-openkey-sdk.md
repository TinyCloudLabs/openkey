---
"@openkey/sdk": minor
---

New `OpenKey.requestRegistryChange({ nodes, spaces?, encryptionNode? })` and `OpenKey.requestRegistryUndo({ historyId })` let an app ask OpenKey to update or restore a person's TinyCloud location registry record on either the popup or embed consent screen, resolving to `{ status: "published", sequence, recordHash } | { status: "cancelled" }`.

Details: TC-3893
