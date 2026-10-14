---
"@openkey/api": minor
"@openkey/web": minor
---

Email sign-in no longer creates an account silently (TC-1114). When a verified code belongs to an email with no OpenKey account, `POST /api/auth/sign-in/email-otp` answers `403` with `code: "NEW_ACCOUNT_CONFIRMATION_REQUIRED"` and a `signupToken`, and creates no user or key. The account and its canonical key are created only by `POST /api/auth/sign-up/email-otp` with `{ email, signupToken }`; the token is single-use, expires after five minutes, is stored only as a hash and works only for the email whose code was verified. Requesting a code is unchanged for known and unknown emails.

The login page, embedded connect widget and recovery page show "No OpenKey account for <email>" with Create, passkey sign-in and recovery choices; the register page confirms automatically. Breaking for direct API callers: a client that signs a new email in with `sign-in/email-otp` must now handle the `403` and call `sign-up/email-otp`.
