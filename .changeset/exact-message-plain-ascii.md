---
"@openkey/web": patch
---

The exact-message views show printable ASCII apostrophes, quotes, angle brackets and ampersands as themselves. Control characters, every non-ASCII character and the backslash read `\uXXXX`, so look-alike characters such as U+2019 and U+201C stay distinct from `'` and `"`, and a typed `\u0027` reads `\u005Cu0027`. The message text is inserted as text on every one of these views. Details: TC-2133
