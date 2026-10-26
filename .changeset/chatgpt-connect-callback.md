---
"@openkey/web": patch
---

`/delegate` returns a delegation to `https://mcp.tinycloud.xyz/chatgpt/connect/callback`, next to the hosted MCP callback `https://mcp.tinycloud.xyz/connect/callback`. The origin and path must match exactly; a query is allowed as for the other registered callbacks. Details: TC-1627
