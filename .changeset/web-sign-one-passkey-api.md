---
"@openkey/api": patch
---

A passkey sign-in made for a web sign request (pop-up or iframe) covers that request's Approve for five minutes, so the user is asked for one passkey instead of two. The cover belongs to that session and that request only, and is recorded only for a user-verified passkey that counts for step-up.

Details: TC-3740
