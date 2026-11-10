---
"@openkey/capability-review": patch
---

The approval screen names three Share-style grants instead of generic rows: the sender's sharing-history KV prefix reads "Read, change and delete your sharing history" (exact `get`, `list`, `put`, `del` under `vault/sender-history/v2/records/` only), the recipient's `files-for-you` mailbox reads "Read and change files shared with you" (still Sensitive), and a `capabilities/read` grant reads "See which permissions are already granted". A KV `del` inside one app folder gets its own row naming the folder ("Delete data associated with `<appId>`"), one row per folder grant. Per-folder app rows, SQL rows, and other users' spaces are unchanged.
