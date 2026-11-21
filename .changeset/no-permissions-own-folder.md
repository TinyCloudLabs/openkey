---
"@openkey/api": minor
"@openkey/web": patch
---

A delegate request that names no `permissions` gets only the app's own folder: kv get, put, del, list and metadata and sql read and write on `applications/<app id>/`, plus capabilities read on the `applications` space, for 7 days unless the request sets its own expiry. This is the grant the SDK asks for when an app passes no manifest. The app id is the sign-in message's domain reversed (`notes.example.com` becomes `com.example.notes`); that domain is the request's `requesterOrigin`, or `cli.tinycloud.xyz` when there is none. `/api/delegate/prepare` returns `ownFolderOnly: true` for such a request, and the approval screen says: "This app didn't say what it needs, so it only gets its own folder." Auto-Sign doesn't sign these requests; they go through normal approval.

Upgrading: a request with no `permissions` used to get the whole `default` space, or the whole `prefix` space when it set one. A caller that needs data outside its own folder lists the permissions it needs. TinyCloud CLI 1.2.5 and earlier send no permissions when the profile has no pinned owner. That covers `tinycloud init`, `tinycloud auth login`, `tinycloud auth rotate` and the secrets commands when they have to sign in again. Those requests get only `applications/xyz.tinycloud.cli/`. Update the CLI to 1.3.0 or later.

Details: TC-3443
