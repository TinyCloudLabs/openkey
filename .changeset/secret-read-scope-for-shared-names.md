---
"@openkey/capability-review": patch
"@openkey/web": patch
---

Secret read rows show the name alone unless it appears in different scopes in the same approval. Scoped rows for a shared name say "Read the secret NAME from SCOPE". The expanded list uses `SCOPE/NAME` for scoped secrets.

Details: TC-4353
