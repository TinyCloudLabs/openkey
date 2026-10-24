---
"@openkey/api": patch
---

Session activation on `POST /api/delegate` and `POST /api/delegate/complete` only activate on known hosts: the allowlisted TinyCloud nodes, and loopback hosts outside production. For any other host the response carries `hostActivated: false` and the web page activates on its own.

Details: TC-1949
