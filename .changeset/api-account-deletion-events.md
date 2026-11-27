---
"@openkey/api": minor
---

Deleting an account records an event with every key address the account held (managed, archived and external), in the deletion's own transaction. The app review account's deletion records one too. `GET /api/internal/account-deletions?after=<id>&limit=<n>` returns the events in ID order behind a dedicated read-only bearer token, with the environment named in every response, and the API deletes events after 60 days.

Details: TC-4416
