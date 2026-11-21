---
"@openkey/api": minor
"@openkey/web": patch
---

A delegate request that names no `permissions` now gets only the app's own folder, not the whole `default` space (or the whole `prefix` space, when it set one). The grant is the same one the SDK asks for when an app passes no manifest: kv get, put, del, list and metadata and sql read and write on `applications/<app id>/`, plus capabilities read on the `applications` space, for 7 days unless the request sets its own expiry. The app id is the sign-in message's domain reversed (`notes.example.com` becomes `com.example.notes`). That domain is the request's `requesterOrigin`, or `cli.tinycloud.xyz` when there is none.

This narrows what such a request gets. A caller that relied on the old default for data outside its own folder must now list the permissions it needs. `/api/delegate/prepare` returns `ownFolderOnly: true` for such a request, and the approval screen says: "This app didn't say what it needs, so it only gets its own folder." Auto-Sign does not sign these requests; they go through normal approval.

Details: TC-3443
