---
"@openkey/api": patch
---

Account deletion now records a receipt in the same transaction that deletes the keys: the SHA-256 of each deleted key's `did:pkh:eip155:1:<address>`, with no user id, email or address. `GET /api/internal/account-deletions?since=<RFC 3339>&after_id=<receipt id>` returns the receipts, in pages of 1000 that continue from the last row, to a server-side caller holding `INTERNAL_DELETION_EXPORT_TOKEN` (503 when unset, 401 when wrong). The new `account_deletion_receipt` table is additive and append-only. No caller of the endpoint is set up.

Details: TC-3353
