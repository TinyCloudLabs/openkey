---
"@openkey/api": patch
---

Account deletion now records a receipt in the same transaction that deletes the keys: the SHA-256 of each deleted key's `did:pkh:eip155:1:<address>`, with no user id, email or address. The digests are pseudonymous. The new `account_deletion_receipt` table is additive and append-only.

Details: TC-3353
