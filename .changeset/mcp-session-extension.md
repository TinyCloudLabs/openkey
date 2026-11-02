---
"@openkey/api": patch
---

A refresh of an MCP connection extends the OpenKey sign-in session that authorized it, up to 30 days after the sign-in began. The extension runs before the provider rotates the token, only for a valid refresh token of a client that authenticates as itself and that the user still consents to, and only as one guarded update: a session that is gone, expired or already 30 days old is not extended and the refresh is answered `invalid_grant`. The new expiry is six days from now (a web use still renews it and re-sends the cookie), never earlier than the current one. Web sign-in renewal is unchanged.
