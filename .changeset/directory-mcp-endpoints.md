---
"@openkey/api": patch
"@openkey/web": patch
---

Register three more restricted TinyCloud MCP addresses, one each for the Claude, Grok and Muse directory listings: the OAuth resources `https://mcp.tinycloud.xyz/claude/mcp`, `/grok/mcp` and `/muse/mcp`, and the ordinary-delegation callbacks `https://mcp.tinycloud.xyz/claude/connect/callback`, `/grok/connect/callback` and `/muse/connect/callback`. Tokens for them last 12 hours, as for the existing MCP resources. The broad and ChatGPT resources and callbacks, operator-configured entries and exact-path matching are unchanged.

Both API and web deployment are required before the matching connector release, and the connector's token-status client must be registered for the new resources (see `docs/resource-server-token-status.md`). No environment change or database migration is required. Sign-in methods, owner consent, privileged scopes and existing OAuth clients are unchanged. Default-branch integration and deployment require explicit owner approval.
