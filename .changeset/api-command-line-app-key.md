---
"@openkey/api": minor
---

A prepared command-line request can ask for one exact app key. The request carries `appKey: { appId, key }`, and OpenKey admits it only when the app's own website lists that exact key in `/.well-known/openkey-app-keys.json`. It signs one key with `decrypt` and `key.create` for at most 7 days, and the owner can only shorten the time the command line asked for. Other command-line requests for app keys are refused as before.

Details: TC-4036
