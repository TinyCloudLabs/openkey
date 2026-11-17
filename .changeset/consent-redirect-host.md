---
"@openkey/web": patch
---

The OAuth consent page now says "After you allow, you'll return to <host>", using the host of the signed `redirect_uri` (never its path or query; nothing is shown if it is missing or unusable), and lists "Use your TinyCloud through the MCP server" and "Stay connected until you disconnect it" when `tinycloud:mcp` and `offline_access` are requested. TC-3188.
