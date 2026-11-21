---
"@openkey/sdk": patch
---

`signMessage()` accepts an optional `presentation` (`SignMessagePresentationV1`: `displayName`, `reason`, `onBehalfOf`, `iconUrl`). The OpenKey window shows it under the verified origin as the app's own, unchecked words; the signed bytes don't include it. The request carries `presentation` only to an OpenKey window whose `openkey:ready` message says `presentation: 1`, and a window without that flag never receives it. `OpenKey.signMessagePresentation` is `1`, a marker that this client sends it. `OpenKey.signMessageShowsApproval` is true when `signMessage()` opens the OpenKey approval screen and false when it goes straight to the person's own wallet.

Details: TC-3706
