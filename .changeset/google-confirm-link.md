---
"@openkey/api": minor
"@openkey/web": minor
---

Google sign-in now requires a verified email and explicit confirmation before creating a new OpenKey account. An existing email no longer links automatically; users sign in to that account and verify an email code before linking Google. Unlinking also requires a fresh email code and a remaining sign-in method. Direct social-sign-in callers must handle `new_account` and `account_exists` callback continuations instead of assuming a session was issued.
