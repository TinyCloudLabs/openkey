---
"@openkey/api": minor
"@openkey/web": minor
---

List and disconnect connected MCP apps on the account page. `GET /api/account/tinycloud-apps` adds a `mcpApps` list (each entry has `kind: "mcp"`, the consent id, app name, host, connection time and scopes) and marks existing entries `kind: "tinycloud"`. `DELETE /api/account/tinycloud-apps/mcp/:consentId` withdraws the signed-in user's own MCP consent through the same consent deletion as the existing disconnect.
