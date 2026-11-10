---
"@openkey/api": minor
"@openkey/tee": minor
---

Add versioned sealing and re-seal maintenance with record-bound authenticated envelopes, an explicitly configured sealing keyring, and resumable offline verification and compare-and-swap updates. Maintenance defaults to verification-only dry runs; applying writes requires explicit opt-in. Default generation-zero writes remain headerless for previous-release compatibility. No schema migration or automatic maintenance invocation is added.
