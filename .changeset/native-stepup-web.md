---
"@openkey/web": minor
---

The native consent page has a step-up screen. It's chosen from an explicit `kind` with no default: `STEPUP` names the framed app and the read-only access it adds, with Allow or Don't allow and no toggles; `SIGNIN` shows the sign-in screen; anything else (no `kind`, an unknown one, or a `STEPUP` that doesn't name its app and spaces) shows an error with nothing to allow. A request for a space the user hasn't set up shows a notice with nothing to allow.

Upgrading: deploy this web after the API, which sends a `kind` on every preview.

Details: TC-3569
