---
"@openkey/web": patch
---

When OpenKey doesn't approve a request because its key, account, host, space or session key differs from what the request was prepared for, the message now says which part differed instead of saying the request changed after it was opened.

Details: TC-3332
