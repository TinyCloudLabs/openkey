---
"@openkey/api": minor
---

Adds `POST /api/oauth/resource/introspect`, a token status check for registered resource servers such as the hosted MCP server, and a registration script and workflow for them. A registered server learns whether an access token issued for its resources is still active, and nothing else; the provider's own `/oauth2/introspect` is unchanged. Details: TC-1627
