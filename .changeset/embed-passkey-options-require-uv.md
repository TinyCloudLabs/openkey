---
"@openkey/api": patch
---

The options that `POST /api/passkey/generate-authenticate-options` returns to the embedded sheet carry `userVerification: "required"`. The server accepts an assertion only when the authenticator verified the person, so the browser refuses an authenticator that can't verify the person at the prompt, before any verify request. Every other option and the `challengeToken` are as Better Auth returned them. An upstream error passes through as it came. The cookie-based `/api/auth/passkey/*` routes return Better Auth's options as they are.

Details: TC-3901
