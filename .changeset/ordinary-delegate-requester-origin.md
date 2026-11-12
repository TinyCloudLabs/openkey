---
"@openkey/api": patch
"@openkey/web": patch
---

Ordinary `/delegate` links accept an optional canonical `requesterOrigin`: HTTPS, or HTTP on exactly localhost, 127.0.0.1 or [::1]. The API binds its host and nondefault port into the prepared SIWE and authorization context. Permission narrowing, managed signing, wallet completion and refreshed review preserve the requester domain. Missing origin preserves the CLI flow; malformed or duplicate parameters and overrides of device, signed-request or prepared-handoff identity are rejected.

Consent labels come from the prepared SIWE: TinyCloud MCP, TinyCloud CLI, or the actual custom host. Caller-reported origin remains explicitly unverified, with no signed app manifest; callback allowlists and node-host policy are unchanged. Deploy API support on every serving instance before this web update, then deploy the matching hosted-MCP update. This patch adds no database migration or environment variable; inherited release changes require their own rollout review.

Successful callback completion uses the same prepared-SIWE attribution: MCP requests return to ChatGPT or the user's MCP client, custom requesters show their host and nondefault port, and CLI wording remains unchanged.

Details: TC-2526
