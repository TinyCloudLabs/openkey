---
"@openkey/api": patch
"@openkey/web": patch
---

Register four more restricted TinyCloud MCP addresses, one each for the Gemini, Perplexity, Mistral and Microsoft 365 Copilot listings: the OAuth resources `https://mcp.tinycloud.xyz/gemini/mcp`, `/perplexity/mcp`, `/mistral/mcp` and `/copilot/mcp`, and the ordinary-delegation callbacks `https://mcp.tinycloud.xyz/gemini/connect/callback`, `/perplexity/connect/callback`, `/mistral/connect/callback` and `/copilot/connect/callback`. Tokens for them last 12 hours, as for the existing MCP resources. The existing resources and callbacks, operator-configured entries and exact-path matching are unchanged.

The authorization-server metadata is also served at the issuer's own path, `/api/auth/.well-known/oauth-authorization-server`, with the same document as `/.well-known/oauth-authorization-server/api/auth`. Google's Connected Apps console looks there first and, by its documentation, uses the first answer it gets, an error included; the path answered 404.

Both API and web deployment are required before the new addresses work, and the connector's token-status client must be registered for the new resources (see `docs/resource-server-token-status.md`). Until then the new addresses refuse every token, and the existing addresses are unaffected. No environment change or database migration is required. Sign-in methods, owner consent, privileged scopes, refresh-token handling and existing OAuth clients are unchanged. Default-branch integration and deployment require explicit owner approval.
