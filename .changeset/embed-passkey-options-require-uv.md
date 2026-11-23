---
"@openkey/api": patch
---

The options that `POST /api/passkey/generate-authenticate-options` returns to the embedded sheet carry `userVerification: "required"`. The server refuses an assertion made without user verification on every ceremony this route issues, and the options said `preferred`, so an authenticator that could not verify the person was accepted by the browser and refused by the server with a 400 after the verify request. With `required` the browser refuses it at the prompt. Every other option and the `challengeToken` are as Better Auth returned them, an upstream error is passed through as it came, and the cookie-based `/api/auth/passkey/*` routes keep their options.

Details: TC-3901
