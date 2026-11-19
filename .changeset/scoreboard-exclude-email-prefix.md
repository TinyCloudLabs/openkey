---
"@openkey/api": patch
---

The scoreboard counts (`/api/internal/scoreboard/protocol-users` and `/app-users`) leave out accounts whose email starts with `qa-sm-smoke-`, the throwaway accounts the secret-manager prompt smoke registers, with no user-id list needed. `SCOREBOARD_EXCLUDE_EMAIL_PREFIXES` (comma-separated, case-insensitive) adds more prefixes. The email is read only to apply the rule and is never returned or logged; responses are still counts only.

Details: TC-3441
