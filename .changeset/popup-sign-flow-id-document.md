---
"@openkey/web": patch
---

The sign pop-up keeps one passkey flow id for the whole document, so a passkey sign-in in the pop-up covers that request's Approve and the person taps one passkey. The pop-up also removes its message listener when it closes.

Details: TC-4233
