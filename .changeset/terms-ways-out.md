---
"@openkey/api": minor
---

Leaving never requires agreeing (TC-3232). With a Terms release set, an account that hasn't accepted it can still delete itself (with its email or passkey step-up), disconnect a TinyCloud, MCP or identity app, stop a renewal lease, revoke a Nostr signing grant or a delegation (owner revocation), cancel a claimed handoff, and deny an approval request, a device sign-in or an OAuth consent. Agreeing to a consent and every other account route still wait for acceptance.
