---
"@openkey/api": patch
---

Requests the API makes to a TinyCloud node during account setup fail on a redirect and never send a request body to another address. Node response bodies are read up to 64 KiB and response headers up to 16 KiB; a larger answer fails the call with `tinycloud_bootstrap_node_response_too_large`, and a redirect fails it with `tinycloud_bootstrap_node_redirect`. The stored failure reason and the outcome message for a failed node call carry the HTTP status and never the node's text. Both new codes are on the log allowlist.

Details: TC-4436
