---
"@openkey/web": patch
---

The sign pop-up and the sign iframe name their own flow on the passkey sign-in and on the approval calls, so one passkey covers sign-in and Approve for that request. The pop-up keeps its flow id in the tab across the login redirect. The login page sends `Content-Security-Policy: frame-ancestors 'none'`, so no page can frame it.

Details: TC-3740
