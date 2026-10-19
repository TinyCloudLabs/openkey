---
"@openkey/api": minor
"@openkey/db": minor
---

TC-1483: counts-only scoreboard metrics. New `POST /api/internal/scoreboard/protocol-users` and `GET /api/internal/scoreboard/app-users` behind their own read-only bearer `OPENKEY_METRICS_READ_TOKEN` (unset = 503), excluding the accounts and OAuth clients listed in `SCOREBOARD_EXCLUDE_USER_IDS` / `SCOREBOARD_EXCLUDE_CLIENT_IDS`. New table `app_sign_in_day`: `/api/delegate` (managed, `/complete`, `/authorize-sign`) and the session path of `/api/delegate/sign` upsert one row per (userId, app origin, UTC day), deleted after 35 days; app origin is `unknown` when the request carries none. Stores nothing else. Requires migration `20261019_0001_app_sign_in_day`.
