---
"@openkey/web": patch
---

A page that has signed in with a passkey starts no second sign-in. The sign-in page stays on screen for a moment while it hands over to the app, and a passkey sign-in made from the email field's suggestions leaves its buttons enabled in that moment. In that moment the passkey button starts no second passkey prompt, the email form sends no code and the social buttons start no provider sign-in.

Details: TC-3901
