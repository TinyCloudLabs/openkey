---
"@openkey/web": patch
---

`/delegate` renders its consent through the shared approval view used by the app popup and iframe: one header naming the requester, the CLI's node, return target and reason in a shared context slot, and each error shown once above the buttons. A user with one key skips the key picker; with several keys the chosen key shows as one line. `/device` opened with a `user_code` shows only the read-only code to check against the terminal, a one-line warning and the sign-in link, with the request details behind a collapsed Details; the editable form returns when that code fails. A typed code is looked up only on submit, so partial codes no longer show an invalid-or-expired error (TC-659, TC-660).
