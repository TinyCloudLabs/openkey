---
"@openkey/api": patch
---

A delegate request that names no `permissions` gets the same app folder the SDK picks for that app. A port other than 80 or 443 is part of the app id: `notes.example.com:8443` gets `applications/com.example.notes_8443/`, and `localhost:5173` gets `applications/localhost_5173/`. A host that isn't a DNS name, such as `[::1]`, gets an app id of `o_` and 16 hex characters made from its host and port. Only a request with no host shares `applications/node.app/`.

Details: TC-3443
