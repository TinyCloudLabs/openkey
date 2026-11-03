---
"@openkey/api": patch
"@openkey/db": patch
---

One-time CLI handoffs are spent when the client acknowledges them, not when it fetches them, so a lost response no longer forces a second owner approval while the first delegation is live.

Device authorization: `POST /api/device-authorizations/token` no longer consumes an approved result. It returns the same encrypted relay on every poll until the client calls the new `POST /api/device-authorizations/:transactionId/ack` with `{ deviceSecret, codeVerifier }` (the poll's own credentials; repeatable), or ten minutes after approval, whichever is first. A client that never acknowledges keeps working: it gets the result, and the result expires. The ciphertext of an approved result that is never acknowledged is cleared from the database once its retention has passed (swept whenever a new device request starts), so un-updated clients do not leave it at rest.

Short codes: `GET /api/delegation-codes/:code` without a claim is unchanged (the first lookup spends the code, "Works once" stays true). With an `OpenKey-Delegation-Claim` header (a client-chosen secret of at least 128 bits, base64url) the code is bound to that claim: the same claim can fetch again until it acknowledges with the new `POST /api/delegation-codes/:code/ack` (same header; repeatable; clears the delegation) or five minutes after redeeming. Any other claim gets the same 404 as an unknown code.

Adds the additive `delegation_code_claim` table (migration `20261103_0001_delegation_code_claim`); it must be deployed before this API image.

Client changes needed in js-sdk (not part of this change): the CLI's `pending-delegation-code` path, Courier's `pending-grant`, and share-envelope's read-once links should send a claim (short codes), persist the result before acknowledging, and call the ack endpoints. Until then the old behavior of each client is unchanged, except that device results now stay pollable until they expire.
