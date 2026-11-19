---
"@openkey/api": patch
---

Bearer session tokens are accepted only in the signed form the `set-auth-token` header returns. OpenKey's own pages read that token from the new session-token route, and the session read doesn't include the token. Every environment except tests sets `BETTER_AUTH_SECRET`.

Details: TC-3422
