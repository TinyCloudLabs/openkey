---
"@openkey/api": minor
"@openkey/web": minor
---

The native sign-in sheet now supports Sign in with Apple (TC-1233):
- PAR accepts `login_method=apple`.
- `GET /api/auth/providers` answers any origin without credentials, so native apps can read it.
- Native social errors are typed and name the provider: cancelled, failed, `apple_email_required`, account exists, and new account (including the Hide My Email notice).
- A `google` or `apple` method whose provider is off stays on the email step.
