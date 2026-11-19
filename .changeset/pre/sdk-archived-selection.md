---
"@openkey/sdk": patch
---

Clear the cached connection when a validated widget response reports `NO_KEY`, and surface the widget's error code and message. An explicit `connect()` selects a new key; failed signing and authorization requests are not retried automatically, and caller-bound SIWE messages and explicit key selections are preserved.

Details: TC-1496.
