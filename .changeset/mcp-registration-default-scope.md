---
"@openkey/api": patch
---

Include `tinycloud:mcp` in the default scope allowlist for OAuth clients that omit `scope` during dynamic registration. This prevents the advertised MCP scope from being rejected as `invalid_scope` when a client subsequently requests it during authorization. User consent, PKCE, resource binding, explicitly narrower scope lists, and privileged TinyCloud signing/delegation restrictions remain enforced.

Existing OAuth clients retain their stored scope lists. After deploying the API update, affected MCP connectors must be recreated to register a new client; signing in again or refreshing tools with the old client ID does not repair its allowlist. No environment changes, schema migration, or MCP server update is required.
