---
"@openkey/web": patch
---

A click on the passkey button while the email field's passkey sign-in is being verified by the server takes that sign-in as its own: the sign-in is reported once and the click starts no second passkey prompt. A click that arrives before the server starts verifying cancels the autofill request and signs in with its own prompt, and a verification that fails leaves the click to sign in with its own prompt.

Details: TC-3901
