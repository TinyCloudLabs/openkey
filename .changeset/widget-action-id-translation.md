---
"@openkey/web": patch
---

The popup and the embedded signing page send the action ids of an encryption grant to `/api/delegate/authorize-sign-preview` and `/api/delegate/authorize-sign` in the spelling the server expects, and read the selection back from the checked preview. Both pages share `lib/widget-selection.ts`.
