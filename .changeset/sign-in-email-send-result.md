---
"@openkey/api": patch
"@openkey/web": patch
---

If the sign-in code email can't be sent, the code request answers `502` with `code: "EMAIL_DELIVERY_FAILED"`, and the API logs the provider error name and HTTP status only.

The login, register, recovery and embedded email forms show "We couldn't send the code to <email>. Please try again in a few minutes.", and add "You can also sign in with a passkey." on forms that offer one.

Details: TC-1954
