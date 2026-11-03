---
"@openkey/api": patch
---

An access token issued for the hosted MCP resources (`https://mcp.tinycloud.xyz/mcp` and `https://mcp.tinycloud.xyz/chatgpt/mcp`) now lasts 12 hours instead of 5 minutes, at the code exchange and on every refresh, so a client that cannot refresh no longer sends the owner back to sign in every five minutes. Every other audience, no audience, and a request naming several audiences keep 5 minutes; refresh tokens keep 7 days. Asking for an MCP resource without the `tinycloud:mcp` scope is refused. Revoking is unchanged: the revoke denylist keeps a token until its own expiry, and the MCP server's token status check, and now OpenKey's own `/oauth2/userinfo` for these tokens, check consent, session and revoke on every call. Do not merge until the MCP server caps how long it serves an unconfirmed token (TC-2395). Details: TC-1366
