---
"@openkey/api": minor
"@openkey/db": minor
---

TC-1483: counts-only scoreboard metrics. New `GET /api/internal/scoreboard/protocol-users` (no input; OpenKey reads data-owning owner addresses from the node's `GET /admin/stats` via `NODE_STATS_URL` + `NODE_STATS_READ_TOKEN`, returns `{count}`; node unset/failing = 503; 30 calls/min per process cap, audit-logged by status and count) and `GET /api/internal/scoreboard/app-users` behind their own bearer `OPENKEY_METRICS_READ_TOKEN` (aggregate counts only; unset = 503), excluding the accounts and OAuth clients listed in `SCOREBOARD_EXCLUDE_USER_IDS` / `SCOREBOARD_EXCLUDE_CLIENT_IDS`. New table `app_sign_in_day`: `/api/delegate` (managed, `/complete`, `/authorize-sign`) and the session path of `/api/delegate/sign` fire-and-forget upsert one row per (userId, app origin, UTC day), deleted after 35 days; app origin is `unknown` when the request carries none. Stores nothing else. Requires migration `20261019_0001_app_sign_in_day`.
