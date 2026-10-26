---
"@openkey/api": patch
---

OAuth token requests accept `https://mcp.tinycloud.xyz/chatgpt/mcp` as a resource, next to the OpenKey base URL and `https://mcp.tinycloud.xyz/mcp`. The match is exact: any other path, a trailing slash, `http` or another host is refused as an invalid resource. Details: TC-1627
