---
"@openkey/web": patch
---

The sign pop-up and the sign iframe name their own flow on the passkey sign-in and on the approval calls, so one passkey covers sign-in and Approve for that request. The pop-up keeps its flow id in the tab across the login redirect. A sign page inside a frame uses that cover only while its Approve button has been in plain view for 500 ms, as reported by an intersection observer v2; otherwise the page asks for the passkey on that tap as it does without a cover, and so does a browser without observer v2 (Safari, Firefox). That tap goes on to the passkey only when the fresh offer is for exactly the request the owner saw; a different request waits for a new tap. The observer samples at most every 100 ms, so an element placed over Approve between two samples is not seen until the next one. The login page sends `Content-Security-Policy: frame-ancestors 'none'`, so no page can frame it.

Details: TC-3740
