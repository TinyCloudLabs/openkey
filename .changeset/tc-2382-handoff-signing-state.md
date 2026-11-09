---
"@openkey/api": patch
"@openkey/web": patch
---

A prepared CLI sign-in handoff is no longer burned by a signing that fails. `/api/delegate/authorize-sign` reserves the handoff in a new `SIGNING` state, signs, and only then spends the context and preview approval tokens and marks the handoff signed. If the managed key fails to sign, the handoff is released: the owner can approve again with the same preview, or cancel. While one signing is in progress a second approval or a cancel answers `409 handoff_signing` instead of "already signed". The owner-revocation handoff releases the same way when its managed signing fails or its signature does not match the reviewed account.

The prepared sign-in page now re-enables Approve and Cancel after a refused or failed signing (a 2xx reply it cannot read still leaves Approve off, since the server may have signed), and counts time on the server's clock rather than the device clock: before the claim, the request's freshness is judged against the `Date` header of the availability reply; after it, the review expires at the claim's expiry minus the reply's `Date` header.

The CLI still has no signal for a handoff the owner never finishes and waits until it expires; that is a CLI change.
