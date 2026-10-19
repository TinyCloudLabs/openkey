---
"@openkey/api": patch
---

Accept canonical RFC UUID version 1–8 `X-Request-Id` values with the RFC variant, normalize them to lowercase, and mint a UUID v4 for absent or malformed values. This matches the shared Tinychat/ptx-dev incoming-ID contract, including v7. Echo the same ID in responses and typed request logs, and propagate it to trusted/configured TinyCloud node HTTP calls, including SDK-owned calls and request-originated background work (TC-959). Signing nonces, authorization contexts, audit IDs, response bodies, and log redaction stay unchanged. No log shipping or deployment is included.

Typed request events now include `request_id_replaced`, a boolean that is true only for a rejected supplied ID and false for valid IDs or absent-header minting. Rejected header text is never logged.

Redirect compatibility changes for calls carrying an injected ID: automatic redirects, including same-origin redirects, now fail closed rather than forwarding correlation or replaying signed requests. Explicit manual/error redirect modes remain intact; configure the final node URL. Calls without an injected ID keep native redirect behavior.

Pin the shared N0 request-ID conformance corpus at canonical commit `76bd10752a52f179ac2a49214f488236d02f8192` (SHA-256 `d995cd9065a9e1c51bc4d3ed041c3bf2a0363e9a04a90f1d07914437d8dd9a80`) and exercise every case against request middleware, including repeated fields and full-string rejection.
