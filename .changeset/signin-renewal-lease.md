---
"@openkey/api": minor
"@openkey/web": minor
---

An app's sign-in can offer automatic renewal (TC-2872). While `OPENKEY_RENEWAL_LEASES` is on and the grant's node is one OpenKey sets leases up on, OpenKey's sign-in frame and popup show the renewal checkbox approval links already have (TC-2933), with the same default-tick rules.

When the owner leaves renewal on, `/api/delegate/authorize-sign` also signs an owner lease (one ability, `tinycloud.delegation/renew` on that grant's CID, for the node's renewer) and returns it beside the grant. An external wallet signs the lease as a second step (`POST /api/delegate/authorize-sign-renewal`). OpenKey only reads the node's renewer identity. It doesn't register the grant or admit the lease, and it keeps no record of either: the app has the node admit the lease, and the node does the renewing. If the lease can't be prepared, no signature is returned.

The choice is sealed with the preview and can't be changed when signing. While leases are off a renewal ask is ignored and the sign-in is unchanged.

When renewal is turned off mid-flow, the message says what the owner can do: untick renewal before anything is signed, or sign in again (ask the app to send the request again) after. With more than one permission listed, the expiry lines read in the plural ("These permissions renew automatically…", "These permissions expire in…"), and the approval button's wait label is "Getting ready…".
