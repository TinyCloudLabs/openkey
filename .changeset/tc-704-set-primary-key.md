---
"@openkey/api": minor
"@openkey/web": minor
---

Let users choose an active managed personal key as their primary TinyCloud key (TC-704). Key settings provide a Primary badge and a confirmed Make primary action; the dashboard badge follows the server flag rather than key order. The confirmation explains that canonical sessions switch owner and spaces from their next token and that no existing data moves.

`POST /api/keys/:keyId/primary` requires an authenticated cookie session from an allowed OpenKey browser origin and rejects bearer credentials. Selection atomically clears the old canonical flag and sets the new one under the user lock and existing partial unique index. Archived primary keys can be replaced and subsequently restored without creating a second primary. External, archived, unowned, other-user, and unsealed keys cannot be selected. `GET /api/keys/:keyId` now includes `isPrimary`.

OAuth canonical identity claims and `tinycloud:manage-key` signing resolve the selected key. Existing app grants and signing-control mode remain unchanged; stale old-owner signing requests are rejected rather than silently signed by the new owner.
