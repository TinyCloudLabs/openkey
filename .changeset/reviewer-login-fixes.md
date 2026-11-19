---
"@openkey/api": patch
"@openkey/web": patch
"@openkey/db": patch
---

Make managed app-review accounts usable end to end: the production migration runner accepts the reviewer migration, a reviewer can load the OAuth consent page, and the review account can approve the hosted MCP's first connect, any personal app in its own space and that app's searchable copy. A failed reviewer start-up step no longer stops the API. The "Use a review code" option appears only inside an OAuth sign-in.

Details: TC-2775
