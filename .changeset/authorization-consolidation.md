---
"@openkey/sdk": minor
---

Add versioned `authorizeTinyCloud()` protocol (v1) that returns
`{ signature, address, signedMessage, selectedActionKeys, permissions }`.
The legacy `signMessage()` remains byte-exact — OpenKey continues to sign
the caller's original bytes. TinyCloud consumers should switch to
`authorizeTinyCloud()` for editable capability review flows and complete
sessions with the returned `signedMessage`.
