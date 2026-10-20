---
"@openkey/api": minor
"@openkey/web": minor
---

Email and passkey sign-up now include a Cloudflare Turnstile check before a new account is created. `POST /api/auth/sign-up/email-otp` requires a `turnstileToken` for new accounts and returns `503` with `code: "REGISTRATION_PAUSED"` when the check is not configured. Sign-in for existing accounts is unchanged. Clients that create accounts through the API must send the token from the widget. The web sign-up screens show the widget and a retry message when the check fails or does not load. Details: TC-1632
