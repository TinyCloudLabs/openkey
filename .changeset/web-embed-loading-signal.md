---
"@openkey/web": patch
---

The embedded widget pages post `openkey:loading` to the embedding origin as soon as their HTML runs, before their scripts load, so the SDK can tell a slow frame from a blocked one.

Details: TC-4438
