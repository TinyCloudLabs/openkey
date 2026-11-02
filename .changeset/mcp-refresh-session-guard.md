---
"@openkey/api": patch
---

An MCP refresh token is checked before the provider rotates it, with the predicate the resource-server token status check uses for access tokens (client, consent, scopes, consent age, authorizing session). A refresh whose connection has ended is answered `400 invalid_grant` and the token stays unrotated, so a client stops retrying and every refresh that succeeds yields a token the status check calls active. An error in the check answers `503 temporarily_unavailable` with `Retry-After`. Unknown, revoked and expired tokens, tokens of another client and tokens without the `tinycloud:mcp` scope go to the provider as before. The token status check calls the same predicate; its answers are unchanged.
