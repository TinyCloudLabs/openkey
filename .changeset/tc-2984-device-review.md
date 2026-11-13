---
"@openkey/web": patch
---

Keep device sign-in requests readable when permissions span multiple spaces, with visible loading and recoverable failure states. Show admin navigation only after server-confirmed admin membership, label only the caller reason actually supplied, and keep technical request details behind Advanced details.

Device reviews now start at the shortest shared expiry preset, or a smaller request maximum/suggestion. Longer access remains an explicit choice on the existing review screen; the signed maximum and request bindings are unchanged.
