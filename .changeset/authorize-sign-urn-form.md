---
"@openkey/api": patch
---

`/api/delegate/authorize-sign` reports a raw `urn:tinycloud:encryption:…` resource in its `selectedActionKeys` and `permissions` as `space: <the urn>`, `path: ""`, the encoding a CLI checks them in, so a prepared `--keys` sign-in is no longer refused after Approve. The signed message and signature are unchanged, and so are the preview, the action ids the window sends, and every non-encryption entry. Details: TC-1783
