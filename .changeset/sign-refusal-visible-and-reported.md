---
"@openkey/web": patch
---

When OpenKey refuses a sign request for a reason a retry cannot change (the website does not list the key, the key-delete rule, an unreadable request), the page now tells the app that asked, once, and keeps Approve disabled. A failure message on the sign card is shown right above the buttons, in view, instead of below the visible area of a short frame. A long account address in the requester's reason now wraps inside the card. Details: TC-2457, TC-2456, TC-2438
