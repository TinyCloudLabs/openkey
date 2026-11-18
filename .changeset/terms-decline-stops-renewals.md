---
"@openkey/api": minor
---

Declining the Terms stops renewals (TC-3232). `POST /api/account/terms/decline`, from the browser only (a request with an Authorization header is refused, 403), revokes the account's renewal leases at the TinyCloud node and then signs the session out. Leases from approval links are stopped under any session, as Settings stops them; sign-in leases, which OpenKey doesn't record, are found by listing the owner's active grants at the node, and only leases to the node's renewer are revoked. The answer comes within a few seconds and the session always ends: `{ signedOut, renewals: { stopped, notStopped, walletRequired, nodeChecked } }`. An outside wallet's leases are reported, not signed for. Answers 409 `terms_not_required` once the account has accepted or no Terms version is set.
