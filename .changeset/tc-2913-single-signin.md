---
"@openkey/sdk": minor
---

Add beginTinyCloudSignIn to reserve the original click's popup and continue from request-bound passkey identity verification to TinyCloud capability approval in that same window. The existing two-step authorization API remains available. The continuation requires a security-critical result verifier and returns only after it accepts the signed result against the original request and pinned identity. TinyCloud SDK consumers use TinyCloud's own verifier.
