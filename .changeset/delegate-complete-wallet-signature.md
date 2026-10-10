---
"@openkey/api": patch
---

`POST /api/delegate/complete` now returns the external wallet signature it verifies, so wallet approvals carry the same session proof as managed approvals. The TinyCloud CLI can verify that proof on callback, paste-code, and device-relay channels; the prior response failed its proof check with `OPENKEY_PROOF_INVALID`. After required-field validation, a non-string `signature` now receives 400 before the authorization context is consumed or the host is activated. Missing, `null`, `false`, and `0` continue to receive the existing required-fields error; these inputs were all refused before side effects. Previously, an array holding a valid signature was accepted on the token path and caused the token-less path to throw. The web sends the wallet's string signature.
