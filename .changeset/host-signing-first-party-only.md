---
"@openkey/api": patch
---

Sign a TinyCloud space host message only for TinyCloud's own apps. An app from another site cannot have the owner's key sign a message that creates a space on the node, and every other message is signed as before.

Details: TC-4115
