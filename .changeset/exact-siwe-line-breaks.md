---
"@openkey/web": patch
---

The 'Original SIWE message' and 'Exact candidate signedMessage' blocks on the prepared CLI sign-in page show each line feed as a real line break. A carriage return, tab, other control character, bidi or zero-width character, non-ASCII character and `<`, `>`, `&`, `"`, `'` stay escaped as `\uXXXX`, so every line break on screen is one line feed in the signed message (TC-2123).
