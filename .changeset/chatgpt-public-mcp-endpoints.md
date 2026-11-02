---
"@openkey/api": patch
"@openkey/web": patch
---

Register the exact public TinyCloud MCP OAuth resource `https://mcp.tinycloud.xyz/chatgpt/mcp` and ordinary-delegation callback `https://mcp.tinycloud.xyz/chatgpt/connect/callback`. Preserve the existing broad MCP resource/callback and additional operator-configured entries; do not allow origin-wide callback matching.

Both API and web deployment are required for the matching SDK candidate. No environment change or database migration is required, and authentication methods, owner consent, privileged signing scopes and existing OAuth clients are unchanged. Reviewer-login compatibility and actual ChatGPT acceptance still require separate proof. Default-branch integration and deployment require explicit owner approval.
Use app-neutral sign-in and key-selection copy on the shared delegation page so hosted users are not told they are authorizing a CLI.

