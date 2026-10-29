---
"@openkey/api": patch
---

A website's sign-in at `/authorize-sign-prepare`, `/authorize-sign-preview` and `/authorize-sign` (a request with no prepared-handoff ticket) may name encryption `decrypt` or `key.create` only under its own `apps/` prefix. Other encryption resources, a bare network URN included, are refused with `app_key_grant_refused` before a context is issued, a preview is approved or a key is unsealed. Prepared-handoff requests are unchanged. Details: TC-2247
