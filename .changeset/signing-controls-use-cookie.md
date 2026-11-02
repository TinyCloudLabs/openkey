---
"@openkey/web": patch
---

The settings page changes TinyCloud signing controls (Auto-Sign, the manage-key mode, per-app grants, disconnecting an app, the primary key) with the cookie session only. A tab that still held a session token from the embedded widget sent these changes as bearer requests, which the API deliberately refuses, so an account created in the widget could not turn Auto-Sign off on openkey.so. The API rule is unchanged. Details: TC-2355
