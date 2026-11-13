---
"@openkey/api": minor
---

TC-2356: `GET /api/internal/metrics` (same `INTERNAL_METRICS_TOKEN` gate) adds a counts-only `users` block: `{ total, buckets, real, realActive: { d1, d7, d30 }, realNew7d }`. Each account lands in exactly one bucket, checked in this order: `internal_team_domain`, `internal_agent_or_qa`, `test_or_throwaway_domain`, `plus_addressed`, `test_like_name`, `never_completed_signup`, `explicit_exclusions` (user ids in `SCOREBOARD_EXCLUDE_USER_IDS`), `bot_like` (50 or more sessions created on one UTC day in the last 30 days). `real` is everyone else; `realActive` counts real accounts by last session update. The response carries no emails, ids or per-user data. If the users query fails, `users` is `null` and the existing counts are unchanged.
