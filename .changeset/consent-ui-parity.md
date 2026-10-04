---
"@openkey/web": patch
---

`/delegate` renders its consent through the shared approval view used by the app popup and iframe: one header naming the requester, the CLI's node, return target and reason in a shared context slot, and each error shown once above the buttons. A user with one key skips the key picker; with several keys the chosen key shows as one line. `/device` opened with a `user_code` shows the code read-only, leaving sign-in as the only action; the editable form returns when that code fails (TC-659, TC-660).
