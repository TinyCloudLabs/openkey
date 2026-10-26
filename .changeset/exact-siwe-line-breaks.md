---
"@openkey/web": patch
---

The 'Original SIWE message' and 'Exact candidate signedMessage' blocks on the prepared CLI sign-in page show each line feed between two lines as a real line break, do not wrap long lines (they scroll sideways), and escape everything else as `\uXXXX`: a carriage return, tab, other control character, bidi or zero-width character, non-ASCII character, `<`, `>`, `&`, `"`, `'`, spaces at the end of a line, and a final line feed. Every line break on screen is one line feed in the signed message, and two different messages never look the same (TC-2123).
