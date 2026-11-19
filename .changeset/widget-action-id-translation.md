---
"@openkey/web": patch
---

The popup, the embedded signing page and the prepared CLI handoff page send the action ids of an encryption grant to `/api/delegate/authorize-sign-preview` and `/api/delegate/authorize-sign` in the spelling the server expects, and read the selection back from the checked preview. The three pages share `lib/widget-selection.ts`.
