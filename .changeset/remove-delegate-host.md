---
"@openkey/api": minor
---

Remove `POST /api/delegate/host`. It signed a `tinycloud.space/host` sign-in with no expiry, for any space and any caller-given node key, with no approval screen, and nothing calls it. It now answers 404.
