---
"@openkey/api": patch
"@openkey/web": patch
---

Make delegation host activation resilient with browser fallback. Server-side activation is now wrapped in try/catch so unreachable hosts (e.g. localhost) no longer cause 500 errors. A `hostActivated` boolean is returned in the response, and the browser only performs activation as a fallback when the server couldn't.
