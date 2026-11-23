---
"@openkey/web": patch
---

A click on the passkey button after a passkey sign-in has completed starts no second passkey prompt. The sign-in page stays on screen for a moment while it hands over to the app, and a passkey sign-in made from the email field's suggestions leaves the passkey button enabled in that moment. The click made a second sign-in and a second session. The button does nothing once the page has signed in.

Details: TC-3901
