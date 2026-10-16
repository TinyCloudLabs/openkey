---
"@openkey/api": patch
---

Accept canonical UUID v4 `X-Request-Id` values, normalize them to lowercase, and mint an ID for absent or malformed values. Echo the same ID in responses and typed request logs, and propagate it to trusted/configured TinyCloud node HTTP calls, including SDK-owned calls and request-originated background work (TC-959). Signing nonces, authorization contexts, audit IDs, response bodies, and log redaction stay unchanged. No log shipping or deployment is included.

Redirect compatibility changes for calls carrying an injected ID: automatic redirects, including same-origin redirects, now fail closed rather than forwarding correlation or replaying signed requests. Explicit manual/error redirect modes remain intact; configure the final node URL. Calls without an injected ID keep native redirect behavior.
