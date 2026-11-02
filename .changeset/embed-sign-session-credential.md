---
"@openkey/web": patch
---

The embedded signing page sends the session token it holds as `Authorization: Bearer <token>` (and no cookies) with its calls to `/api/delegate/authorize-sign-prepare`, `-preview` and `authorize-sign`, the way `lib/api.ts` does for the other calls the widget makes. An iframe on another site does not send OpenKey's session cookie, so these calls had no credential there. Without a token the page sends cookies as before.
