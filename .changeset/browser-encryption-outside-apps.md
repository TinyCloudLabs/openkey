---
"@openkey/api": patch
---

A website's sign-in may name encryption `decrypt` or `key.create` only under its own `apps/` prefix, a bare network URN included. At `/authorize-sign-prepare`, `/authorize-sign-preview` and `/authorize-sign` (a request with no prepared-handoff ticket) and at `/api/keys/:keyId/sign` (the SIWE text or the same text as `0x` hex, for any origin that is not on the first-party list in `services/first-party-origins.ts`), anything else is refused with `app_key_grant_refused` before a context is issued, a preview is approved or a key is unsealed. A ReCap that cannot be read is refused rather than passed. Prepared-handoff requests are unchanged. Sites that sign in with the TinyCloud web SDK without a `manifest` ask for whole-network decrypt and are refused; the `packages/sdk/README.md` sign-in example now passes a manifest. Details: TC-2247
