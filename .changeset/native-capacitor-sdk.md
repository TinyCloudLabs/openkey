---
'@openkey/sdk-capacitor': minor
---

Add the Capacitor 8 native sign-in SDK with iOS and Android secure storage, TinyCloud delegation verification, renewal, revocation, and a secure TinyCloud session storage adapter. First release starts at 0.1.0.

Transient revoke failures leave a secure pending-revoke entry with the key, token, attempt count, and expiry for bounded automatic retry. Network failures, temporary unavailability, HTTP 5xx, and 429 remain retryable; other errors settle the entry. Failed discovery is retried on the next call. Terminal renewal outcomes clear the session and best-effort revoke rotated grants; failed new sign-in attempts preserve an existing session and its in-flight renewal. Equivalent normalized permission subsets share one renewal flight.

Queued session writes and sign-out removal now compare the stored session identity before changing it. Sign-out revokes a replacement session that arrives during an earlier revoke. Corrupt pending-revoke records are cleared, and retry expiry uses refresh-token issue or rotation time plus seven days, capped at `renewableUntil` plus five minutes.
