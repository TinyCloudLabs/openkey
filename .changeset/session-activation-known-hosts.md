---
"@openkey/api": patch
---

Session activation on `POST /api/delegate` and `POST /api/delegate/complete` only activates on known hosts: the allowlisted TinyCloud nodes, and loopback hosts outside production. For any other host the response carries `hostActivated: false` and `spaceReady: false`, and the web page activates on its own. A known host whose activation fails or times out still reports `spaceReady: null`.

Details: TC-1949
