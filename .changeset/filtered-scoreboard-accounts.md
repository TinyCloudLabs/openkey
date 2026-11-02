---
"@openkey/api": patch
---

Add real and excluded account aggregates and apply the same CSV-derived identity rules to scoreboard counts. Export normalized, deduplicated kind/value identities, including exact email domains; report the domain-only excluded count in internal metrics. Keep advisory patterns separate. Use SCOREBOARD_EXCLUSIONS for the new resolver; retain SCOREBOARD_EXCLUDE_USER_IDS for older releases during rollback. Details: TC-1480
