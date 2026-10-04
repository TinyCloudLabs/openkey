---
"@openkey/api": patch
---

`/api/delegate/complete` and the managed approval require `tinycloud.capabilities/read` only when the request baseline grants it (the default consent set, or a CLI `permissions` request that asks for it). A CLI request without it, such as `tc secrets list` asking only for `tinycloud.kv/list`, can now be approved instead of failing with "capabilities/read is required for this delegation". The subset check against the original request is unchanged (TC-658).
