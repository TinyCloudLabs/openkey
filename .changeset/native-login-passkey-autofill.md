---
"@openkey/web": patch
---

The sign-in page lists the device's passkeys in the email field's suggestions, so a saved passkey signs in without a button tap; the request ends when the step changes, when the passkey button is pressed, and when the page closes. In the native sign-in sheet, a passkey prompt that ends with no passkey used shows a message and a button to continue with an email code, and the email-code sign-in that follows offers to add a passkey to the device, whatever other passkeys the account has.

Details: TC-3715
