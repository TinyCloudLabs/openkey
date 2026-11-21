---
"@openkey/capability-review": patch
---

`buildOwnerRevocationSiwe` checks every field it writes into the message the owner's key signs: the owner DID, the CID and the nonce must have their expected shapes, and the domain must be a host (an optional port, no whitespace or path). A field that doesn't is refused, so none can add a line to the signed text, whichever caller passes it. Details: TC-3232
