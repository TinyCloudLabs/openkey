---
"@openkey/api": minor
"@openkey/web": minor
---

Add `/delegate` page and API endpoints for CLI auth flow. Users authenticate with a passkey, select a managed or external key, review permissions on a consent screen, and approve the delegation. Supports both server-side TEE signing (managed keys) and two-step prepare/complete flow (external wallet keys).
