---
"@openkey/api": minor
"@openkey/web": minor
---

Ordinary `/delegate` links (no device transaction) only return the signed delegation to a loopback callback or a registered app callback endpoint (the hosted MCP's `/connect/callback`; more via `VITE_DELEGATE_CALLBACK_URLS`), never follow a callback redirect, refuse unsafe node hosts, show the node, return destination, and expiry, warn before a paste code, and require confirmation for a node OpenKey does not recognize (`node`/`tee.node.tinycloud.xyz` are built in; more via `VITE_DELEGATE_NODE_ORIGINS`). `/api/delegate/prepare` and `/api/delegate` cap delegation lifetime at 30 days. Wallet-key `/api/delegate/complete` approvals bind to the address in the signed SIWE, verify the signature against it before consuming the context or activating, and report the signed SIWE's expiry. `/api/delegate/sign`, `/api/delegate/host`, and `/api/keys/:keyId/sign` refuse `deviceTransactionId` with `device_transaction_unsupported`. Device links are unchanged.
