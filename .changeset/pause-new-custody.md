---
"@openkey/api": patch
---

Add `OPENKEY_PAUSE_NEW_CUSTODY` (default off). Literal `true` refuses new accounts and managed Ethereum/Nostr keys before insertion or sealing with `NEW_CUSTODY_PAUSED`, while existing login, identities, signing and approvals stay available. Social signup callbacks retain Better Auth's generic error UI. Production activation and same-image flag rollback are documented in the deployment guide.
