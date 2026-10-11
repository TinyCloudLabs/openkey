---
"@openkey/web": patch
"@openkey/api": patch
---

`/delegate` says before approval when approving will also finish setting up the requested TinyCloud space (managed key, Auto-Sign on, trusted node), or that it won't (Auto-Sign off, external wallet). After approval it says whether the space is ready or why setup didn't finish. `/api/delegate/prepare` returns a read-only `spaceSetup` field (TC-801).
