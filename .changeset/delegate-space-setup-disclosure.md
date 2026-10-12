---
"@openkey/web": patch
"@openkey/api": patch
---

`/delegate` says before approval when approving will also finish setting up the requested TinyCloud space (managed key, Auto-Sign on, trusted node), or that it won't (Auto-Sign off, external wallet). After approval it says whether the space is ready or why setup didn't finish. `/api/delegate/prepare` returns a read-only `spaceSetup` field (TC-801).

Approval responses report `spaceReady: true` only when TinyCloud confirmed the space. It is `false` when setup didn't finish and `null` when host activation failed, so readiness is unknown. `/api/delegate/prepare` keeps its top-level `spaceId`, and `spaceSetup` is `null` when `TINYCLOUD_BOOTSTRAP_ON_SIGN=off`.
