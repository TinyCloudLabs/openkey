---
"@openkey/api": minor
"@openkey/web": minor
---

An app's sign-in can offer automatic renewal (TC-2872). While `OPENKEY_RENEWAL_LEASES` is on and the grant's node is one OpenKey sets leases up on, OpenKey's sign-in frame and popup show the renewal checkbox approval links already have (TC-2933), with the same default-tick rules.

When the owner leaves renewal on, `/api/delegate/authorize-sign` registers the signed grant with its node. It then signs an owner lease (one ability, `tinycloud.delegation/renew` on that grant's CID, for the node's renewer), records it for the owner (no approval request) and has the node admit it, all before returning. An external wallet signs the lease as a second step (`POST /api/delegate/authorize-sign-renewal`). If the lease can't be set up, no signature is returned.

The choice is sealed with the preview and cannot be changed when signing. While leases are off a renewal ask is ignored and the sign-in is unchanged.

If any step after the lease is reserved fails, OpenKey stops that lease at the node before returning the failure. When renewal is turned off mid-flow, the message says what the owner can do: untick renewal before anything is signed, or sign in again (ask the app to send the request again) after. With more than one permission listed, the renewal line reads "These permissions renew automatically…", and the approval button's wait label is "Getting ready…".
