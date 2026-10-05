---
"@openkey/api": minor
"@openkey/web": minor
---

A user's canonical TinyCloud key is now shown as their primary key. `GET /api/keys` returns `isPrimary` for each key (true only for the active managed canonical key). Every delegation `/api/delegate` and `/api/delegate/complete` return carries `primary`, read from the database for the key that signed (always false for an external wallet), so the CLI callback, paste code and device relay all report it. When a `/delegate` request names no owner, the key picker preselects the primary key; other keys stay available behind "Use a different key", with a warning that each key is a separate account owner with its own data. A named owner still wins, and users without a primary key get the plain list. The picker no longer offers "Generate New Key", whose keys never become primary (TC-703).
