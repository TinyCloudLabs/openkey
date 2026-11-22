---
"@openkey/api": patch
"@openkey/web": patch
---

A renewal lease on a grant that reaches secrets (any permission on a `secrets/` key or prefix, or decrypt on a whole encryption network) is refused unless the owner confirmed "Renew sensitive access?", and the grant's window (expiry less Not Before or Issued At) must be 7 days or less. The confirm travels in the owner's choice as `sensitiveConfirmed: true`, is sealed in the preview, and approving cannot add it. A grant whose permissions OpenKey cannot read is refused a lease. The approval screen asks for the confirm on exactly the grants the API requires it for.

Details: TC-3821
