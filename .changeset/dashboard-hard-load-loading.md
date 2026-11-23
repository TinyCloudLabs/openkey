---
"@openkey/web": patch
---

A hard load of the dashboard shows the loading state until the session read answers, in the server-rendered page too, so a signed-out visitor never sees the signed-in shell for a moment.

Details: TC-3902
