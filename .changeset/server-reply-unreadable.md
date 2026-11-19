---
"@openkey/web": patch
---

The embedded signing page, the popup and the prepared CLI handoff page count a reply from `authorize-sign-prepare`, `authorize-sign-preview` or `authorize-sign` as an answer only when it is a JSON object with the fields the next step needs. A 2xx reply with an empty body, text that is not JSON, or an object without those fields shows "OpenKey couldn't finish this request" with a short explanation, signs nothing, and reports a failure to the host (`SERVER_REPLY_UNREADABLE`). The HTTP status is shown in Advanced details and written to the console, never the reply.
