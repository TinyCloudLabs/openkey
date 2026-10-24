---
"@openkey/api": patch
"@openkey/web": patch
---

The sign-in code request checks the Resend result (TC-1954). When Resend returns an error, or the send throws, `POST /api/auth/email-otp/send-verification-otp` answers `502` with `code: "EMAIL_DELIVERY_FAILED"`, and the API log gets an `otp_delivery_failed` line with the provider error name and HTTP status only. A successful send and a missing Resend key behave as before.

The login, register, recovery and embedded email forms show "We couldn't send the code to <email>. Please try again in a few minutes." for that response, with "You can also sign in with a passkey." on forms that offer a passkey.
