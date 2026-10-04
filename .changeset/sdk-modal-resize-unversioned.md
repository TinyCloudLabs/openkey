---
"@openkey/sdk": patch
---

Fix (TC-647): the iframe modal now grows to fit the OpenKey widget for `connect`, `signMessage` and `signTypedData`, so Approve is visible without scrolling. In 0.10.0 these unversioned flows bound no resize correlation, so every `openkey:resize` was dropped and the modal stayed 400px tall.

A modal with no versioned request now accepts a resize that carries no `requestId`, only from its own iframe on the OpenKey origin, and still clamps it to 85% of the viewport. A modal with a versioned request binds its `requestId` + `protocolVersion` as soon as it is created and still drops any resize that does not carry that exact pair. The `openkey.so` sign widget now sends a plain resize when its request is unversioned.
