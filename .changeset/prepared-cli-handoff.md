---
"@openkey/api": minor
"@openkey/web": minor
---

Add a versioned prepared-SIWE CLI handoff on `/delegate` that binds the SDK's original message and public session key to a single-use approval, previews the exact signed bytes, and delivers the signed result through a strict loopback callback or local paste code. Existing delegate links remain unchanged.

Owner revocation review also displays a copyable full permission ID for comparison with the CLI. Signing uses the configured web origin and a request expiry allowance of ten minutes plus one minute of clock skew; the signed message expires within ten minutes of issuance.
