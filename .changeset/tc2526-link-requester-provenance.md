---
"@openkey/web": patch
---

Show ordinary approval links as link-authored host claims with a clear sender warning, rather than assigning first-party requester names from their SIWE domain. Preserve server-verified approval, device and prepared-handoff attribution.

An ordinary link now also says where the approval will be delivered, inside the same warning. A callback that exactly matches one of OpenKey's built-in registered endpoints reads "Your approval will be delivered to the TinyCloud MCP service" and adds that the request may come from someone else's session. A loopback callback reads "an app on this device (127.0.0.1:<port>)". The name comes only from OpenKey's own table, never from the link, and neither line names the requester.
