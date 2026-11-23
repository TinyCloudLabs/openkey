---
"@openkey/api": patch
---

OpenKey creates an owner's first TinyCloud space only when the owner signs in on one of TinyCloud's own apps or approves a request on an OpenKey page. An app from another site can't create it by asking for a signature, even with Auto-Sign on. Once the first space exists, an app from another site can create the owner's other spaces, such as a public space.

Details: TC-4115
