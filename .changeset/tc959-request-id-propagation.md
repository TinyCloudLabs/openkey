---
"@openkey/api": patch
---

Accept canonical UUID v4 `X-Request-Id` values, normalize them to lowercase, and mint an ID for absent or malformed values. Echo the same ID in responses and typed request logs, and propagate it to trusted/configured TinyCloud node HTTP calls, including SDK-owned calls and request-originated background work (TC-959). Signing nonces, authorization contexts, audit IDs, response bodies, and log redaction stay unchanged. No log shipping or deployment is included.
