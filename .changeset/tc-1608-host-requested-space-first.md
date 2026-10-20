---
"@openkey/api": patch
---

`POST /api/delegate` hosts the TinyCloud space the client asked for before it responds, when approving creates a missing canonical space (managed key, Auto-Sign on). Inside the setup's existing lock, the managed key signs the same host SIWE the setup already signed (peer id, then `tinycloud.space/host` on that one space), the node accepts it, and OpenKey re-activates the session it just signed to confirm the space is hosted. `spaceReady: true` is returned only after that confirmation. The other five spaces and the seeding still run in the background, in the same run, and skip the space that is already hosted. No new ability is signed.

If the space is not hosted within `TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS` (default 10000 ms, capped at 60000), the response is `spaceReady: null`, `spacePending: true` and `spaceError: "tinycloud_requested_space_timeout"` (clients that wait on `spacePending` with `spaceReady: null` keep waiting), and the setup continues in the background. If the node refuses or the setup fails, the response keeps its existing `spaceReady: false` and `spaceError`. `TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS` now applies only to `/api/keys/:id/sign`.

Every request the setup makes to the TinyCloud node now has a timeout (`TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS`, default 15000 ms, for the peer id, host and activation requests; `TINYCLOUD_BOOTSTRAP_NODE_INVOKE_TIMEOUT_MS`, default 30000 ms, for the schema, seeding and encryption-network requests; both capped at 60000), so a hung call fails the run and releases its lock instead of holding it through the heartbeat. A timeout is recorded under `tinycloud_bootstrap_node_timeout`.

A failed setup started by an approval is retried in the background without another approval: three retries after 5 s, 15 s and 45 s (`TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS`: comma-separated milliseconds, or `off`). Each retry unseals the managed key again instead of holding it while it waits. A failed state keeps its `failureCode` and `failureReason` while it is retried; a successful run clears them.

`tinycloud_bootstrap_background_failed` and `tinycloud_bootstrap_background_completed` now carry `duration_ms` and `attempt`, and, for approvals, `requested_space_hosted` (`yes`, `no` or `timeout`: whether the requested space was hosted before the response). New error codes: `tinycloud_bootstrap_node_timeout`, `tinycloud_bootstrap_space_not_hosted` (TC-1608).
