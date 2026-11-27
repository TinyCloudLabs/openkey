---
"@openkey/web": patch
---

The approval face shows each scope of a secret as its own row: "Read the secret NAME in scope SCOPE", with the name and the scope set apart. The grouped "Read N secrets" row lists a scoped secret as `SCOPE/NAME`, and N and the Sensitive banner equal the number of secret keys the request names.

Details: TC-4349
