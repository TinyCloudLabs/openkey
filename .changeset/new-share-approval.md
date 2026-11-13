---
"@openkey/sdk": minor
"@openkey/api": minor
"@openkey/web": minor
---

Add a typed new-share approval that returns a generated share identifier and an exact signed permission for the current session. The new SDK entry reserves its popup from the original click and requires the TinyCloud consumer to verify the signed result before using it. Security-relevant session changes cancel the pending request. A capped automatic refresh that leaves the session authority unchanged preserves an in-progress approval.
