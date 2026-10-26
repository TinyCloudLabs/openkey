---
"@openkey/web": patch
---

Every exact-message view of a message being signed (the 'Exact bytes being signed' block of the CLI, popup, iframe and widget approvals, the native consent and owner revocation pages, and the raw message view of the legacy delegate page) shows each line feed between two lines as a line break and does not wrap long lines. A carriage return, tab, other control character, bidi or zero-width character, non-ASCII character, `<`, `>`, `&`, `"`, `'`, runs of two or more spaces, spaces at the end of a line and a final line feed are shown as `\uXXXX`. The Copy text button still copies the message as it is (TC-2133).
