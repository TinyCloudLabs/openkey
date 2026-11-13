---
"@openkey/api": minor
"@openkey/web": minor
---

The approval screen's "Approval expires: 30d (Change)" line is replaced (TC-2933).

- Where the requester signed a renewal request (`renewal: { version: 1, leaseLifetimeSeconds }` on a signed approval request), the line is one checkbox: ticked, "This permission renews automatically for up to 90 days"; unticked, "This permission expires in 30 days", with the real lengths filled in. It starts ticked only when the request's signed `purpose` is `standing` and nothing in it reaches secrets or decrypt; a task, or a request with no purpose, starts unticked. Ticking it on a request that reaches secrets or decrypt first asks "Renew sensitive access?", and turning renewal on there uses a 7-day window.
- Where the box shows, the app-key "This access lasts until <date>." line is no longer shown beside it (a fixed end date is wrong while renewal is on, and repeats the line while it is off); it is unchanged elsewhere.
- Everywhere else the line reads "This permission expires in <window>", with no box.
- How long the permission lasts, and how long renewal can go on (90 days, 6 months, 1 year or a typed time, never more than the request signed or one year), are changed under a closed "How long it lasts" fold. There is no "(Change)" link.
- Ticked, the approve body carries `renewal: { choice: "leased", leaseLifetimeSeconds }`; unticked, `renewal: { choice: "finite" }`. After the grant is signed and registered with its node, OpenKey signs, as the owner, a lease whose only ability is `tinycloud.delegation/renew` on `urn:cid:<the grant's CID>`, for the renewer identity the node advertises at `/.well-known/tinycloud/node-keys` (checked against the node's `/info` id), ending at approval time plus the chosen lease. The node admits it, and the encrypted approval result gains `renewalChoice` (`leased` or `finite`) and, when leased, `renewal: { version, approvedLeaseLifetimeSeconds, approvedAt, receipt }`. Each step is saved on the approval request (new nullable `renewal` column), so a retry reuses the saved grant and lease instead of signing new ones. If the lease can't be set up, nothing is approved: "OpenKey couldn't set up renewal. Nothing was approved. Try again."
- An external wallet signs the lease as a second signature: `POST /api/delegate/complete` answers `{ renewalSignature: { message } }` instead of saving, the screen shows "Sign once more to turn on renewal", and the wallet's signature goes to the new `POST /api/approval-requests/:id/renewal-signature`. Declining it approves nothing.
- The API's `@tinycloud/node-sdk` and `@tinycloud/sdk-core` move from 2.11.0 to 3.12.0-beta.22, `@tinycloud/node-sdk-wasm` from 1.7.6 to 1.7.9-beta.0, and `@tinycloud/share-envelope` from 1.4.1-beta.1 to 1.6.0-beta.1.
