---
"@openkey/api": patch
"@openkey/web": patch
---

OpenKey reads a sign-in message's expiry and times the way the TinyCloud node does, from one shared parser, and refuses to sign a sign-in message with a control character, U+2028 or U+2029, so a fake `Expiration Time:` line in the statement can no longer set the expiry shown or capped. Details: TC-3826
