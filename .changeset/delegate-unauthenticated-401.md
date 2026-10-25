---
"@openkey/api": patch
---

A request to the delegate routes (`/api/delegate/authorize-sign-prepare`, `-preview`, `authorize-sign`, `prepare`, `complete` and `/`) without a session answers 401 `{"error":"Unauthorized"}`, and a bearer token from a site that is not an OpenKey web origin answers 403. The refusal was returned to a router that has its own error handler and was not passed on, so Hono answered with an empty 200.
