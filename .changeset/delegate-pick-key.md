---
"@openkey/web": patch
---

`/delegate` no longer preselects the primary key when the account has several keys and the CLI request names no owner: the picker shows and the user chooses which key signs. A single key, or a requested owner, is still selected automatically. The approval stays bound to the chosen key; the API refuses a signature with any other key.
