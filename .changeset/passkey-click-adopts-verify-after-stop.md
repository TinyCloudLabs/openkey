---
"@openkey/web": patch
---

A click on the passkey button takes the email field's passkey sign-in as its own whenever the server starts verifying that sign-in, including when the click arrives while the sign-in options are being fetched. The click cancels the passkey prompt until the server starts verifying, then waits for the verification: a verified sign-in is reported once and the click starts no second passkey prompt, and a verification that fails leaves the click to sign in with its own prompt.

Details: TC-3901
