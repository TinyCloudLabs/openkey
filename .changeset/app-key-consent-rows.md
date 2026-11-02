---
"@openkey/api": patch
"@openkey/web": patch
---

The approval view lists encryption keys under `apps/` as their own "App keys" group, one row per ability (create, decrypt, block, unblock) for an exact key or a prefix, with the key path in monospace and, beneath decrypt rows, a line stating the signed expiry. A `key.delete` action is listed as a row that cannot be granted and has no checkbox. Requests for app keys that do not come through a website's sign-in (command line, device sign-in, `/api/keys/:id/sign`, prepared handoff) are answered with the sign-in wording, and a CoordinationOS signing request that names an app key or `key.delete` is recorded as a `wrong_capability` denial. Details: TC-1777
