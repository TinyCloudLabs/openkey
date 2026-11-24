---
"@openkey/api": patch
"@openkey/db": patch
---

The session token stored in the database is a hash of the token. Everyone signs in once after the update and AI connectors reconnect.

Details: TC-3422
