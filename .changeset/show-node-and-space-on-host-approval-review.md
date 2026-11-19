---
"@openkey/capability-review": patch
---

`readSpaceHostFacts` lists the spaces a request asks the signer to host and the node key on its `URI:` line, read from the bytes that are signed. `recognizeHostPeer` checks a configured node's key for each space against that key, reporting a known node (the configured origin that matched) or not confirmed. `abbreviateSpaceId`, `abbreviateDid` and `samePeerDid` are exported for display and comparison.

Details: TC-1950
