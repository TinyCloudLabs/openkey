---
"@openkey/web": patch
---

Outside an embedded frame, every API call from the web app uses the cookie session; the session token the embedded widget stores in the tab is used only inside an embedded frame. The settings page changes TinyCloud signing controls (Auto-Sign, the manage-key mode, per-app grants, disconnecting an app, the primary key) with the cookie session and never a token, even inside an embedded frame. A tab that still held the widget's token sent these changes as bearer requests, which the API deliberately refuses, so an account created in the widget could not turn Auto-Sign off on openkey.so; and when the token and the cookie belonged to different accounts the page showed one account's settings and wrote to the other. The API rule is unchanged. Details: TC-2355
