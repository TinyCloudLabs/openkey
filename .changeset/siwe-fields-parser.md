---
"@openkey/capability-review": patch
---

Adds `parseSiweFields` and `siweExpirationTime`: a sign-in message's fields read the way the TinyCloud node reads them (lines split on `\n` only), so a fake `Expiration Time:` line hidden in the statement is never taken for the real one. Details: TC-3826
