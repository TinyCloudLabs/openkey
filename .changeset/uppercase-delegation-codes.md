---
"@openkey/api": patch
"@openkey/web": patch
---

Delegation short codes are now shown in upper case. `POST /api/delegation-codes` returns `ABCD-EF23` instead of `abcd-ef23`, from the same 32-symbol base32 alphabet (`A-Z2-7`, 40 bits). Codes are still stored and looked up in lower case, and `GET /api/delegation-codes/:code` still accepts any case, so codes issued before this change and CLIs that lower-case the code before the lookup keep working. `/delegate` accepts either case from the API and shows the code in upper case. Device-login codes were already upper case and are unchanged.
