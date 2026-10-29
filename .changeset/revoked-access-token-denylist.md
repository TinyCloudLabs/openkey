---
"@openkey/api": minor
"@openkey/db": patch
---

A JWT access token revoked at `/oauth2/revoke` is now reported inactive by the resource server token status check until it expires. The provider's own revoke changes nothing for a JWT access token, so OpenKey records the token's key (a SHA-256 of its signed part, never the token) when the provider answers 200 and the token verifies and was issued to the calling client. A revoke that cannot be recorded is answered 503. Adds one table, `revoked_access_token`. Details: TC-2104
