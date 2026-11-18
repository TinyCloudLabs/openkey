---
"@openkey/api": minor
"@openkey/capability-review": minor
---

Declining the Terms stops renewals (TC-3232). `POST /api/account/terms/decline`, from the browser only (a request with an Authorization header is refused, 403), revokes the account's renewal leases at the TinyCloud node and then signs the session out.

- Leases from approval links are stopped under any session, as Settings stops them.
- Sign-in leases, which OpenKey doesn't record, are found by listing the owner's active grants at the node; only leases to the node's renewer, with a well-formed lease CID, are revoked. Leases found before a listing fails are still revoked. A second pass runs once an app's admission window has passed, for a lease admitted just after the listing.
- The list covers the default TinyCloud node and the chain-1 owner identity OpenKey's sign-ins use; the answer says so in `nodeScope`.
- An outside wallet's leases are reported, not signed for.
- The answer: `{ signedOut, renewals: { stopped, notStopped, walletRequired, nodeChecked, nodeScope } }`. `stopped` counts leases the node confirmed revoked; `notStopped` leases found but not confirmed (including recorded ones still under way when the answer was due); `walletRequired` recorded leases only the outside wallet that signed them can stop; `nodeChecked` false means the node list was not read to the end, so some renewals may continue. The stop answers within 3 seconds and sign-out may take up to 3 more; the session always ends.
- Answers 409 `terms_not_required` once the account has accepted or no Terms version is set. No new lease is signed while the account hasn't accepted: every route that signs one waits for acceptance.

`buildOwnerRevocationSiwe` validates the owner DID, CID, nonce and domain itself, for every caller.
