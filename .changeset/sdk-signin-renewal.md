---
"@openkey/sdk": minor
---

`authorizeTinyCloud` takes `renewal: { version: 1, leaseLifetimeSeconds, purpose? }` beside `expiryChangeable: true` (TC-2872). It asks OpenKey's sign-in window to offer automatic renewal. The result carries the owner's `renewalChoice` and, when renewal was left on, the admitted lease as `renewal` (the approval-renewal codec). With an external wallet, the wallet signs the lease after the grant, and declining it fails the sign-in. A malformed ask, or one without `expiryChangeable: true`, throws before anything opens.
