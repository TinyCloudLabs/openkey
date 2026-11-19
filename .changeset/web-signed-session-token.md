---
"@openkey/web": patch
---

The embedded widget and the sign-in pages keep the signed session token the API returns with each sign-in, and ask the API for it after registering, recovering or a Google or Apple sign-in. Signing out of the widget reports the session as ended only when the API confirms the token no longer works.

Details: TC-3422
