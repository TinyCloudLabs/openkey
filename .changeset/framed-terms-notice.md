---
"@openkey/web": patch
---

An OpenKey page in a frame on another site shows a notice when the account has not agreed to the Terms of Service, in place of a blocked frame. The Terms screen needs the browser's cookie session, which a frame on another site does not have, so the notice opens the Terms in a window of its own. The frame watches the account with its session token and reloads once the account has agreed.

Details: TC-3766
