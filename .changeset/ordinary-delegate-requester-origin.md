---
"@openkey/api": patch
---

Ordinary `/delegate` links accept an optional canonical `requesterOrigin`: HTTPS, or HTTP on exactly localhost, 127.0.0.1 or [::1]. The API binds its host and nondefault port into the prepared SIWE and authorization context. Permission narrowing, managed signing, wallet completion and refreshed review preserve the requester domain. Missing origin preserves the CLI flow; malformed or duplicate parameters and overrides of device, signed-request or prepared-handoff identity are rejected.

The domain remains caller-reported, not verified requester identity. Deploy this API support on every serving instance before the matching web and hosted-MCP updates. This patch adds no database migration or environment variable; inherited release changes require their own rollout review.

Details: TC-2526
