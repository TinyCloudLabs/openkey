---
"@openkey/sdk": minor
---

Delegate registration to popup when in iframe embed mode

Google OAuth sends `X-Frame-Options: DENY`, preventing sign-in with Google inside an iframe. The embed connect widget now delegates registration to the parent SDK, which opens a popup window for the full registration flow (email/Google + passkey). After completion, the session token is relayed back to the iframe via postMessage.
