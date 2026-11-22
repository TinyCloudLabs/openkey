---
"@openkey/web": patch
---

Every approval screen with a length says how long the access lasts: "This app's access to your data lasts {length}." A device sign-in reads "This device's access to your data lasts {length}." Over two days the line names the day it ends ("29 days, until Dec 17"). On a screen that signs the message as written, the /delegate fallback included, the length runs to the message's own Expiration Time. A one-off signature that grants no access shows no length. On a signed approval request that can open all your secrets or all your encrypted data, the approval starts at 1 hour and the "How long it lasts" choice goes up to what the app asked for.

Details: TC-3111
