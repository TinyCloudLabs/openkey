---
"@openkey/web": patch
---

Show the device sign-in review near the top of the page, with visible loading, recoverable load-failure and expired-request states. List every requested permission on the main summary, including access in spaces other than `default`. Show admin navigation only after server-confirmed admin membership, label only the caller reason actually supplied, and keep technical request details behind Advanced details.

Device reviews now start at the shortest shared expiry preset (one hour), or a smaller request maximum/suggestion, instead of the requested maximum. A CLI request for 7 days therefore starts at 1 hour; longer access remains an explicit choice on the existing review screen, and the signed maximum and request bindings are unchanged.
