---
"@openkey/db": minor
"@openkey/api": minor
---

TC-1711: background retry for failed TinyCloud setup. New additive column `tinycloud_bootstrap_state.sweepAttempts` (migration `20261021_0001_tinycloud_bootstrap_sweep_attempts`, default 0). A timer in the API process (60 s tick, `TINYCLOUD_BOOTSTRAP_SWEEP=off` disables it) retries rows whose failure code is in the retryable allowlist, at 5 min, 30 min, 2 h and 6 h after the last attempt, at most four sweep runs per row, ten rows per tick. Each sweep claim is a compare-and-set on the observed state, so approvals, other ticks and other instances cannot sign the same row concurrently. Approval runs reset the counter to 0. Sweep log events are `tinycloud_bootstrap_sweep_*`.
