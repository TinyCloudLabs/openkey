---
"@openkey/sdk": patch
---

`signMessage()` accepts an optional `presentation` (`SignMessagePresentationV1`: `displayName`, `reason`, `onBehalfOf`, `iconUrl`). The OpenKey window shows it under the verified origin as the app's own, unchecked words; the signed bytes are unchanged. The request carries `presentation` only to an OpenKey window whose `openkey:ready` message says `presentation: 1`, and an older window never receives it. `OpenKey.signMessagePresentation` is `1`, a marker that this client sends it.
