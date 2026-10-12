---
"@openkey/api": patch
"@openkey/web": patch
---

`POST /api/delegate` no longer waits for the whole TinyCloud space setup when approving creates a missing canonical space (managed key, Auto-Sign on). It waits up to `TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS` (default 2500 ms, shared with `/api/keys/:id/sign`), then returns `spaceReady: null` with `spacePending: true` and finishes setup in the background. An approval that arrives while setup is already running also reports `spacePending: true` instead of a setup failure. Clients that only read `spaceReady` treat this as unknown readiness, as before. `/api/delegation-codes` accepts and returns `spacePending`. On openkey.so, the done screen says the space is being set up instead of showing a warning (TC-945).

`/api/keys/:id/sign` now signs and reports `tinycloudBootstrap.errorCode: 'tinycloud_bootstrap_crashed'` when bootstrap throws before the budget, instead of returning 500. The synchronous bootstrap budget is capped at 60000 ms to prevent oversized timer values from overflowing.
