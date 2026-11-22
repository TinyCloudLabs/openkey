---
"@openkey/api": patch
---

A passkey sign-in made for a web sign request (pop-up or iframe) covers that request's Approve for five minutes, so the user is asked for one passkey instead of two. The cover belongs to that session and that request only, and is recorded only for a user-verified passkey that counts for step-up. The approval that passes on the cover spends it with a single delete, so of several parallel approvals for one flow exactly one passes on the cover. An offer that the cover waives carries `flowCover: true`, so the sign page can hold the cover to its visibility check.

Details: TC-3740
