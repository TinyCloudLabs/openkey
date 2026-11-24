---
"@openkey/capability-review": patch
---

The summary row "Read secrets" reads "Read the secret NAME" when exactly one secret is named. Row labels separate the kind from the target with a colon ("Secret values (read): vault/secrets/NAME", "Secret data: all secrets", "Permission check: default"). Another user's database administration reads "Another user's SQL database (manage)". `protocolHeadline()` gives a sign-in the heading "Sign in to {app}".

Details: TC-3921
