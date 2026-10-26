---
"@openkey/api": patch
---

An MCP refresh token whose authorizing web session has ended or expired is answered with `invalid_grant` before the provider rotates it, so a client stops retrying and does not receive tokens that are inactive on arrival. A failed session lookup answers 503 `temporarily_unavailable`. Refresh tokens without the `tinycloud:mcp` scope are unchanged.
