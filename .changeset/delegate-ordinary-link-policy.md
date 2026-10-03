---
"@openkey/api": minor
"@openkey/web": minor
---

Ordinary `/delegate` links (no device transaction) only return the signed delegation to a loopback callback or a registered app origin, refuse unsafe node hosts, show the node, return destination, and expiry, and require confirmation for a node OpenKey does not recognize. `/api/delegate/prepare` and `/api/delegate` cap delegation lifetime at 30 days. Wallet-key `/api/delegate/complete` approvals bind to the address in the signed SIWE, so the versioned path no longer fails with `key-mismatch`. `/api/delegate/sign`, `/api/delegate/host`, and `/api/keys/:keyId/sign` refuse `deviceTransactionId` with `device_transaction_unsupported`. Device links are unchanged.
