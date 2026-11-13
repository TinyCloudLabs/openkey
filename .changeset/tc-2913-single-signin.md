---
"@openkey/sdk": minor
---

Add beginTinyCloudSignIn to reserve the original click's popup and continue from request-bound passkey identity verification to TinyCloud capability approval in that same window. The existing two-step authorization API remains available. Callers must verify the final signed SIWE against the provisional identity before activating a session.
