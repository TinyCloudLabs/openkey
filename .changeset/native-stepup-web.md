---
"@openkey/web": minor
---

The native consent page has a step-up screen (TC-3569). It is chosen from an explicit `kind`: `STEPUP` names the framed app and the read-only access it adds, with no toggles, and Allow or Don't allow; a missing `kind` or `SIGNIN` is the sign-in screen as before; any other value, or a `STEPUP` that does not name its app and spaces, is an error with nothing to Allow. A request for a space the user has not hosted shows a notice and nothing to Allow. Nothing changes for sign-in requests, and step-up requests stay off behind `OPENKEY_NATIVE_STEPUP_ENABLED` until the API, this screen and the revoke sweeper are all deployed.
