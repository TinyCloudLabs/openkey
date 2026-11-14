---
"@openkey/web": patch
---

The sign pages no longer offer Approve for a request the server will refuse: when a site that is not first-party asks, through the message-signing path, to decrypt or create encryption keys outside its own `apps/` folder, the page shows "This site can't ask for that access, so OpenKey didn't approve this request.", keeps Approve off and tells the app once with `APP_KEY_GRANT_REFUSED`. Nothing is sent to be signed. The server rule is unchanged. Details: TC-2928
