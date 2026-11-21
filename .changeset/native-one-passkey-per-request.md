---
"@openkey/api": patch
---

A passkey sign-in made for a pending native consent request counts as that request's approval passkey, so the user isn't asked for a second passkey at Approve. It covers only that request, for the session that signed in, for five minutes, and it needs a user-verified passkey that counts for step-up. The login page names the request in a new `x-openkey-passkey-flow` header, and a new `approvalPasskeyMethod` column on native requests records which gate let each approval through. Lowering the approval setting, manage-key mode, enabling an app, account deletion, passkey enrolment and removal, and key export or recovery still ask for their own passkey.

Details: TC-3596
