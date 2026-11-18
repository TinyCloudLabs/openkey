---
"@openkey/sdk": minor
---

`authorizeTinyCloud` takes `renewal: { version: 1, leaseLifetimeSeconds, purpose? }` beside `expiryChangeable: true` (TC-2872). It asks OpenKey's sign-in window to offer automatic renewal. The result carries the owner's `renewalChoice` and, when renewal was left on, the owner-signed lease as `renewal` (the approval-renewal codec). OpenKey doesn't send the lease to the node: the app registers the grant, then has the node admit the lease with `admitOwnerRenewalLease`. With an external wallet, the wallet signs the lease after the grant, and declining it fails the sign-in. A malformed ask, or one without `expiryChangeable: true`, throws before anything opens.
