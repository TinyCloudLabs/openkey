---
"@openkey/api": patch
---

Server bootstrap no longer overwrites account space registry records; it creates only missing ones with create-only puts and rebuilds the index rows from KV.
