---
"@openkey/web": patch
---

The approval screen names three Share-style grants instead of generic rows: the sender's sharing-history KV prefix reads "Read, change and delete your sharing history", the recipient's `files-for-you` mailbox reads "Read and change files shared with you" (still Sensitive), and a `capabilities/read` grant reads "See which permissions are already granted". A KV `del` inside one app folder gets its own row naming the folder. Per-folder app rows unchanged.
